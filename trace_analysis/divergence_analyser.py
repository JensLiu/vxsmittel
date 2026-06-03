from trace_db import TraceDatabase, TraceRecord
from kernel_db import KernelDatabase
from instruction_flow_analyser import FlowAnalyser, FlowInstruction


class DivergenceAnalyser:
    def __init__(
        self,
        kernel_db: KernelDatabase,
        trace_db: TraceDatabase,
        trace_db_tmp: TraceDatabase,
    ):
        self.kernel_db = kernel_db
        self.trace_db = trace_db
        self.trace_db_tmp = trace_db_tmp
        self.flow_analyser = FlowAnalyser(kernel_db, trace_db)
        self.cmp_flow_analyser = FlowAnalyser(kernel_db, trace_db_tmp)

    def analyse_data_flow(self):
        # TODO: assert (clusters, sockets, cores, wids) are the same in both trace DBs
        clusters = self.trace_db.get_clusters()
        for cluster in clusters:
            sockets = self.trace_db.get_sockets(cluster)
            print(f"Analysing {cluster}: sockets={sockets}")
            for socket in sockets:
                cores = self.trace_db.get_cores(cluster, socket)
                print(f"  {socket}: cores={cores}")
                for core in cores:
                    wids = self.trace_db.get_wids(cluster, socket, core)
                    print(f"    {core}: wids={wids}")
                    for wid in wids:
                        self.analyse_flow_by_id(cluster, socket, core, wid)
                        id = f"{cluster}/{socket}/{core}/wid{wid}"
                        control_flow_divergence_points, data_flow_divergence_points = (
                            self.analyse_flow_by_id(cluster, socket, core, wid)
                        )
                        first_data_divergence = (
                            data_flow_divergence_points[0]
                            if data_flow_divergence_points
                            else None
                        )
                        if first_data_divergence:
                            instr, instr_cmp = first_data_divergence
                            self.analyse_data_divergent_flow(instr, instr_cmp, id)

    def analyse_flow_by_id(self, cluster, socket, core, wid):
        trace = self.flow_analyser.get_flow(cluster, socket, core, wid)
        trace_cmp = self.cmp_flow_analyser.get_flow(cluster, socket, core, wid)
        return self.analyse_flow_by_trace(trace, trace_cmp)

    def analyse_flow_by_trace(self, trace, trace_cmp):
        control_flow_divergence_points = []
        data_flow_divergence_points = []
        for instr, instr_cmp in zip(trace, trace_cmp):
            # control divergence: different PC or warp active mask
            if (instr.pc, instr.tmask) != (instr_cmp.pc, instr_cmp.tmask):
                control_flow_divergence_points.append((instr, instr_cmp))
                break
            # data divergence: different architectural value (address-free,
            # chunk-invariant); compared per lane via data_sig.
            sig = self.data_sig(instr)
            sig_cmp = self.data_sig(instr_cmp)
            if sig is not None and sig_cmp is not None and sig != sig_cmp:
                data_flow_divergence_points.append((instr, instr_cmp))
                break
        return control_flow_divergence_points, data_flow_divergence_points

    @staticmethod
    def _to_int(s):
        return int(s, 16) if isinstance(s, str) else int(s)

    @staticmethod
    def _active_lanes(mask):
        # mask string is MSB-first: lane j is active iff mask[len-1-j] == '1'
        if not mask:
            return []
        n = len(mask)
        return [j for j in range(n) if mask[n - 1 - j] == "1"]

    @staticmethod
    def _byte_mask(byteen):
        # per-byte enable (bit i -> byte i) expanded to a value bitmask
        m, i = 0, 0
        while byteen:
            if byteen & 1:
                m |= 0xFF << (8 * i)
            byteen >>= 1
            i += 1
        return m

    CSR_OPS = {"CSRRW", "CSRRWI", "CSRRS", "CSRRSI", "CSRRC", "CSRRCI"}
    CSR_ALWAYS_WRITE = {"CSRRW", "CSRRWI"}

    def data_sig(self, flow: FlowInstruction):
        """Architectural effect of `flow`, address-free and invariant to
        commit/coalescing chunking, so it is comparable across runs that differ
        only in translation.  Returns a dict of effects (or None for none):

          - int lane key       -> register writeback value  (load / ALU / CSR read)
          - int lane key       -> (byteen, masked store data)          [stores]
          - ('csr', addr) key  -> (op, written source)                 [CSR writes]

        The CSR-write entry matters because a `csrw` is wb==0/rd==x0, so without
        it a CSR divergence is only seen much later when the CSR is read back.
        """
        commits = [r for r in flow.trace if r.event == "commit"]
        if not commits:
            return None  # never retired (e.g. truncated trace)
        ex = commits[0].other_payload.get("ex")
        wb = commits[0].other_payload.get("wb")

        # store: per-lane (byteen, masked data) from core-req-wr (no rd writeback).
        if ex == "LSU" and wb == "0":
            result = {}
            recs = [
                r
                for r in flow.trace
                if "memsched" in r.event and r.action == "core-req-wr"
            ]
            for r in recs:
                data = r.other_payload.get("data")
                byteen = r.other_payload.get("byteen")
                valid = r.other_payload.get("valid")
                if not data or not byteen:
                    continue
                for lane in self._active_lanes(valid):
                    if lane < len(data) and lane < len(byteen):
                        be = self._to_int(byteen[lane])
                        result[lane] = (be, self._to_int(data[lane]) & self._byte_mask(be))
            return result or None

        result = {}
        # register writeback (load / ALU / CSR read): fold per-lane across chunks
        # (a load may commit one lane per chunk, each with its own tmask).
        if wb == "1":
            for c in commits:
                data = c.other_payload.get("data")
                if not data:
                    continue
                for lane in self._active_lanes(c.other_payload.get("tmask")):
                    if lane < len(data):
                        result[lane] = self._to_int(data[lane])

        # CSR write effect (in addition to any rd read-back above).
        self._add_csr_write(flow, result)

        return result or None

    def _add_csr_write(self, flow: FlowInstruction, result: dict):
        disp = next((r for r in flow.trace if "dispatch" in r.event), None)
        if disp is None:
            return
        p = disp.other_payload
        op = p.get("op")
        if op not in self.CSR_OPS:
            return
        addr = p.get("addr")
        if p.get("use_imm") == "1":
            val = self._to_int(p.get("imm") or "0")
            src = ("imm", val)
            nonzero = val != 0
        else:
            rs1 = p.get("rs1_data") or []
            lanes = self._active_lanes(p.get("tmask"))
            vals = tuple(self._to_int(rs1[l]) for l in lanes if l < len(rs1))
            src = ("reg", vals)
            nonzero = any(v != 0 for v in vals)
        # CSRRW always writes; set/clear write only when the source is non-zero
        # (so a plain `csrr` = CSRRS rd,csr,x0 is a pure read and adds nothing).
        if op in self.CSR_ALWAYS_WRITE or nonzero:
            result[("csr", addr)] = (op, src)




    def analyse_data_divergent_flow(
        self, instr: FlowInstruction, instr_cmp: FlowInstruction, id=None
    ):
        print(
            f"{id}: First data flow divergence at instruction {instr.uuid} (PC={instr.pc}):"
        )
        print(
            f"  Trace 1: pc={hex(instr.pc) if instr.pc else '???'} {instr.instruction_text} uuid=#{instr.uuid}"
        )
        print(
            f"  Trace 2: pc={hex(instr_cmp.pc) if instr_cmp.pc else '???'} {instr_cmp.instruction_text} uuid=#{instr_cmp.uuid}"
        )
        # Effect diff (address-free): this is the actual divergence. Keys are
        # either int lanes (reg writeback / store data) or ('csr', addr) tuples.
        sig = self.data_sig(instr) or {}
        sig_cmp = self.data_sig(instr_cmp) or {}
        keys = set(sig) | set(sig_cmp)
        lane_keys = sorted(k for k in keys if isinstance(k, int))
        csr_keys = sorted((k for k in keys if not isinstance(k, int)), key=str)

        def _fmt(v):
            return hex(v) if isinstance(v, int) else v

        for k in lane_keys + csr_keys:
            v1, v2 = sig.get(k), sig_cmp.get(k)
            mark = "   <-- DIFF" if v1 != v2 else ""
            label = f"lane {k}" if isinstance(k, int) else f"csr {k[1]}"
            print(f"    {label}: trace1={_fmt(v1)}  trace2={_fmt(v2)}{mark}")

        # Full stage-by-stage trace, side by side (lines marked when they differ,
        # ignoring the leading cycle number). Addresses will show as differences
        # here - that is expected (VA vs PA); the per-lane diff above is the signal.
        print("  --- full trace (trace1 / trace2) ---")
        for r, rc in zip(instr.trace, instr_cmp.trace):
            divergent = (
                r.raw_line[r.raw_line.find(":") :]
                != rc.raw_line[rc.raw_line.find(":") :]
            )
            if divergent:
                print("+--")
            print(f"{'|' if divergent else ' '} {r.raw_line}")
            print(f"{'|' if divergent else ' '} {rc.raw_line}")
            if divergent:
                print("+--")


if __name__ == "__main__":
    # s = "1279: cluster0-socket0-core3-execute-lsu0-memsched core-req-wr: valid=1111, addr={0x3ffe27fe, 0x3ffe2ffe, 0x3ffe37fe, 0x3ffe3ffe}, byteen={0xf, 0xf, 0xf, 0xf}, data={0x0, 0x0, 0x0, 0x0}, tag=0xc000000212000007a185000 (#51539607585)"
    # from parsing import parse_trace_line
    # print(f"Parsing line: {s}")
    # record = parse_trace_line(s, line_no=1)
    # print(record)

    from instruction_flow_analyser import FlowAnalyser

    trace_db = TraceDatabase.from_file("bug/mmu.log")
    trace_db_cmp = TraceDatabase.from_file("bug/non-mmu.log")
    kernel_db = KernelDatabase.from_file("bug/kernel.dump")

    # flow_analyser = FlowAnalyser(kernel_db, trace_db)
    # trace = trace_db.get_trace_by_uuid("cluster0", "socket0", "core0", 86)
    # trace = trace_db.get_trace_by_uuid("cluster0", "socket0", "core0", 81604381061)
    # trace_cmp = trace_db_cmp.get_trace_by_uuid("cluster0", "socket0", "core0", 33)

    # flow = flow_analyser.get_flow_by_trace(trace)
    # flow_cmp = flow_analyser.get_flow_by_trace(trace_cmp)
    # print(flow)

    # lsu_trace = [trace for trace in flow.trace if "lsu" in trace.event]
    # lsu_trace_cmp = [trace for trace in flow_cmp.trace if "lsu" in trace.event]

    # for t, tc in zip(lsu_trace, lsu_trace_cmp):
    #     if (t.raw_line != tc.raw_line):
    #         print(f"{t.raw_line} \n {tc.raw_line}")
    #         print("\n")

    data_trace_analyser = DivergenceAnalyser(kernel_db, trace_db, trace_db_cmp)
    data_trace_analyser.analyse_data_flow()
    # control_flow_divergence_points, data_flow_divergence_points = data_trace_analyser.analyse_flow_by_id("cluster0", "socket0", "core3", 1)
    # first_data_divergence = data_flow_divergence_points[0] if data_flow_divergence_points else None
    # if first_data_divergence:
    #     instr, instr_cmp = first_data_divergence
    #     print(f"First data flow divergence at instruction {instr.uuid} (PC={instr.pc}):")
    #     print(f"  Trace 1: {instr.log_text}")
    #     print(f"  Trace 2: {instr_cmp.log_text}")
