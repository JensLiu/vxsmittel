from dataclasses import dataclass
from typing import List, Optional, Tuple
from trace_db import TraceDatabase, TraceRecord
from kernel_db import KernelDatabase


@dataclass(frozen=True)
class FlowInstruction:
    line_no: int
    uuid: int
    wid: Optional[int]
    pc: Optional[int]
    tmask: Optional[str]
    function_name: str
    instruction_text: str
    first_cycle: Optional[int]
    last_cycle: Optional[int]
    events: List[Tuple[str, int]]
    trace: List[TraceRecord]


class FlowAnalyser:
    def __init__(self, kernel_db: KernelDatabase, trace_db: TraceDatabase):
        self.kernel_db = kernel_db
        self.trace_db = trace_db

    def get_flow(
        self, cluster: str, socket: str, core: str, wid: int
    ) -> List[FlowInstruction]:
        exec_trace = []
        seen_uuids = set()
        for entry in self.trace_db.get_uuids_by_component(cluster, socket, core, wid):
            uuid = entry["uuid"]
            if uuid in seen_uuids:
                continue
            seen_uuids.add(uuid)
            flow_inst = self.get_flow_by_trace(
                self.trace_db.get_trace_by_uuid(cluster, socket, core, uuid)
            )
            if flow_inst is not None:
                exec_trace.append(flow_inst)
        return exec_trace

    def get_flow_by_trace(self, trace: List[TraceRecord]) -> Optional[FlowInstruction]:
        if not trace:
            return None

        first = trace[0]
        line_no = first.line_no
        cluster, socket, core, wid, uuid = (
            first.cluster,
            first.socket,
            first.core,
            first.wid,
            first.uuid,
        )
        raw_events = [r.event for r in trace]
        # merge events with same name into (event, count) tuples
        events = []
        for event in raw_events:
            if not events or events[-1][0] != event:
                events.append((event, 1))
            else:
                events[-1] = (events[-1][0], events[-1][1] + 1)

        if not (
            events[0][0] == "schedule"
            and (
                events[-1][0] == "commit"
                or "commit" in set(e[0] for e in events)
                and "coalescer" in events[-1][0]
            )
        ):
            print(
                f"Warning: Unexpected event sequence for {cluster}/{socket}/{core}/wid{wid} uuid={uuid}: "
                f"{' -> '.join(event for event, count in events)}"
            )
            # return None

        # Collect full trace including LSU/memory subsystem events
        trace_records = self.trace_db.get_trace_by_uuid(cluster, socket, core, uuid)
        pcs = {r.pc for r in trace if r.pc is not None}
        if len(pcs) > 1:
            print(
                f"Warning: Multiple PCs for {cluster}/{socket}/{core}/wid{wid}"
                f" uuid={uuid}: {set(hex(p) for p in pcs)}"
            )
        pc = pcs.pop() if len(pcs) == 1 else None
        tmask = next((r.tmask for r in trace if r.tmask is not None), None)

        return FlowInstruction(
            line_no=line_no,
            uuid=uuid,
            wid=wid,
            pc=pc,
            tmask=tmask,
            function_name=(
                self.kernel_db.find_function_by_pc(pc)
                if pc is not None
                else "<unknown-pc>"
            ),
            instruction_text=(
                self.kernel_db.instructions.get(pc).text
                if pc is not None and pc in self.kernel_db.instructions
                else "<unknown-inst>"
            ),
            first_cycle=trace_records[0].cycle,
            last_cycle=trace_records[-1].cycle,
            events=events,
            trace=trace_records,
        )
