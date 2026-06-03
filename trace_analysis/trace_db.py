from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

BOOT_PC = 0x80000000

@dataclass(frozen=True)
class TraceRecord:
    line_no: int
    raw_line: str
    cycle: Optional[int]
    cluster: str
    socket: str
    core: str
    event: str
    wid: int
    pc: Optional[int]
    tmask: Optional[str]
    action: Optional[str]
    pipeline_payload: Optional[dict]
    lsu_payload: Optional[dict]
    other_payload: Optional[dict]
    uuid: int

    def __str__(self) -> str:
        s =  f"TraceRecord(line_no={self.line_no}, cycle={self.cycle}, component=({self.cluster}, {self.socket}, {self.core}), uuid = {self.uuid}, event={self.event}, wid={self.wid}, pc={self.pc}, tmask={self.tmask}, action={self.action}, "
        if self.pipeline_payload is not None:
            s += f"pipeline_payload={self.pipeline_payload}, "
        if self.lsu_payload is not None:
            s += f"lsu_payload={self.lsu_payload}, "
        if self.other_payload is not None:
            s += f"other_payload={self.other_payload}, "
        s += f")"
        return s

class TraceDatabase:
    def __init__(self, trace: List[TraceRecord]):
        self._trace: List[TraceRecord] = trace
        self._db: Dict[str, Dict[str, Dict[str, Dict[int, Dict[str, Dict[int, List[TraceRecord]]]]]]] = {}  # indexing
        self._booted: Dict[Tuple[str, str, str], bool] = {}  # per-core boot detection
        for record in trace:
            self.__process_trace(record)

    @classmethod
    def from_file(cls, trace_file: str) -> "TraceDatabase":
        from parsing import parse_trace_line
        with open(trace_file, "r") as f:
            records = []
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("***"):
                    continue
                record = parse_trace_line(line, line_no=line_no)
                if record is not None:
                    records.append(record)
        return cls(records)

    def __process_trace(self, record: TraceRecord):
        (cluster, socket, core, wid, uuid) = (
            record.cluster,
            record.socket,
            record.core,
            record.wid,
            record.uuid,
        )

        # Drop pre-boot records: ignore until we see BOOT_PC for this core
        core_key = (cluster, socket, core)
        if not self._booted.get(core_key, False):
            if record.pc == BOOT_PC:
                self._booted[core_key] = True
            else:
                return

        cluster_db = self._db.setdefault(cluster, {})
        socket_db = cluster_db.setdefault(socket, {})
        core_db = socket_db.setdefault(core, {})
        wid_db = core_db.setdefault(wid, {"uuid_trace": {}, "wid_uuid_map": {}})

        uuid_trace: Dict[int, List[TraceRecord]] = wid_db["uuid_trace"]
        wid_uuid_map: Dict[int, List[Dict[str, int]]] = wid_db["wid_uuid_map"]

        uuid_trace.setdefault(uuid, []).append(record)
        wid_uuid_map.setdefault(wid, []).append({"uuid": uuid, "log_line_no": record.line_no, "cycle": record.cycle})

    def get_trace_by_uuid(
        self,
        cluster: str,
        socket: str,
        core: str,
        uuid: int,
        wid: Optional[int] = None,
    ) -> List[TraceRecord]:
        core_db = self._db.get(cluster, {}).get(socket, {}).get(core, {})
        if wid is not None:
            wid_db = core_db.get(wid, {})
            return wid_db.get("uuid_trace", {}).get(uuid, [])
        # Collect from all wid buckets, sorted by cycle then line_no
        records = []
        for wid_db in core_db.values():
            uuid_db: Dict[int, List[TraceRecord]] = wid_db.get("uuid_trace", {})
            if uuid in uuid_db:
                records.extend(uuid_db[uuid])
        records.sort(key=lambda r: (r.cycle or 0, r.line_no))
        return records

    def get_uuids_by_component(self, cluster: str, socket: str, core: str, wid: int) -> List[int]:
        wid_db = self._db.get(cluster, {}).get(socket, {}).get(core, {}).get(wid, {})
        wid_uuid_map: Dict[int, List[Dict[str, int]]] = wid_db.get("wid_uuid_map", {})
        return wid_uuid_map.get(wid, [])

    def get_clusters(self) -> List[str]:
        clusters = list(self._db.keys())
        return sorted([cluster for cluster in clusters if "cluster" in cluster])

    def get_sockets(self, cluster: str) -> List[str]:
        sockets = list(self._db.get(cluster, {}).keys())
        return sorted([socket for socket in sockets if "socket" in socket])

    def get_cores(self, cluster: str, socket: str) -> List[str]:
        cores = list(self._db.get(cluster, {}).get(socket, {}).keys())
        return sorted([core for core in cores if "core" in core])  # filter out non-core entries like "core1-issue-lsu0"

    def get_wids(self, cluster: str, socket: str, core: str) -> List[int]:
        wids = list(self._db.get(cluster, {}).get(socket, {}).get(core, {}).keys())
        return sorted([wid for wid in wids if wid is not None]) # filter out None entries if any

if __name__ == "__main__":
    from parsing import parse_trace_line
    example_trace_path = "example_trace.log"
    records = []
    with open(example_trace_path, "r") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("***"):
                continue
            record = parse_trace_line(line, line_no=line_no)
            if record is not None:
                records.append(record)

    trace_db = TraceDatabase(records)
    uuids = trace_db.get_uuids_by_component("cluster0", "socket0", "core1", 2)
    print(f"UUIDs for cluster0/socket0/core1/wid2: {uuids}")
    trace = trace_db.get_trace_by_uuid("cluster0", "socket0", "core1", 25769803802)
    for record in trace:
        print(record)
