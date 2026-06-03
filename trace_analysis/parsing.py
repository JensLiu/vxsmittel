import re
from typing import Dict, Iterable, List, Optional, Tuple
from trace_db import TraceRecord

def split_top_level_csv(text: str) -> List[str]:
    items: List[str] = []
    cur: List[str] = []
    depth_brace = 0
    depth_bracket = 0
    for ch in text:
        if ch == "{" and depth_bracket >= 0:
            depth_brace += 1
        elif ch == "}" and depth_brace > 0:
            depth_brace -= 1
        elif ch == "[" and depth_brace >= 0:
            depth_bracket += 1
        elif ch == "]" and depth_bracket > 0:
            depth_bracket -= 1

        if ch == "," and depth_brace == 0 and depth_bracket == 0:
            item = "".join(cur).strip()
            if item:
                items.append(item)
            cur = []
            continue
        cur.append(ch)

    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items

def parse_optional_int(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    value = text.strip()
    if not value:
        return None
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value, 10)
    return None


def summarise_data_fields(fields: Dict[str, str]) -> str:
    if not fields:
        return ""

    primary_keys = [
        "ex",
        "op",
        "instr",
        "rd",
        "wb",
        "sop",
        "eop",
        "addr",
        "tag",
        "pid",
        "ibuf_idx",
        "batch_idx",
        "valid",
        "pmask",
        "offset",
        "byteen",
        "flags",
        "data",
        "rs1_data",
        "rs2_data",
        "rs3_data",
    ]

    out: List[str] = []
    skip_keys = {"wid", "pc", "tmask", "sid"}
    for key in primary_keys:
        if key in fields and key not in skip_keys:
            out.append(f"{key}={fields[key]}")

    for key in sorted(fields.keys()):
        if key in skip_keys:
            continue
        if key not in primary_keys:
            value = fields[key]
            if value:
                out.append(f"{key}={value}")
            else:
                out.append(key)

    return ", ".join(out)


def find_first_available_int(
    records: Iterable[TraceRecord], field_name: str
) -> Optional[int]:
    for record in records:
        value = parse_optional_int(record.fields.get(field_name))
        if value is not None:
            return value
    return None


def parse_payload(payload_str: str):
    """
    Parses a raw payload string into a Python dictionary.
    Handles standard values (PC=0x123) and array values (data={0x0, 0x1}).
    """
    # Group 1: The Key (word characters)
    # Group 2: The Value (either anything that isn't a comma/bracket, OR a full {...} block)
    payload_pattern = re.compile(r"(\w+)=([^,{}]+|\{[^}]+\})")
    parsed_data = {}
    for key, value in payload_pattern.findall(payload_str):
        value = value.strip()
        # Check if the value is an array block: {0x80007888, 0x8000786c}
        if value.startswith("{") and value.endswith("}"):
            # Strip the brackets and split by comma into a Python list
            inner_str = value[1:-1].strip()
            if inner_str:
                parsed_data[key] = [v.strip() for v in inner_str.split(",")]
            else:
                parsed_data[key] = []  # Handle empty brackets {}
        else:
            # Standard single value
            parsed_data[key] = value
    return parsed_data



def parse_trace_line(line: str, line_no: int) -> Optional[TraceRecord]:
    # log patterns
    LSU_PATTERN = r"^\s*(?:(?P<cycle>\d+):\s*)?(?P<component>cluster\d+-socket\d+-core\d+-execute-lsu\d+)\s+(?P<action>Rd Req|Wr Req|Rsp):\s*(?P<payload>.*?)\s*\(#(?P<uuid>\d+)\)\s*$"
    CACHE_MEM_PATERN = r"^\s*(?:(?P<cycle>\d+):\s*)?(?P<component>[\w-]+)\s+(?P<action>(?:core|bank|mem)-(?:rd|wr|req|rsp)(?:-[a-z]+)*\[\d+\]):\s*(?P<payload>.*?)\s*\(#(?P<uuid>\d+)\)\s*$"
    PIPELINE_PATTERN = r"^\s*(?:(?P<cycle>\d+):\s*)?(?P<component>cluster\d+-socket\d+-core\d+-(?:fetch|schedule|issue\d+-[a-z]+|execute-[a-z0-9-]+|commit))(?:\s+(?P<action>req|rsp|branch))?:\s*(?P<payload>.*?)\s*\(#(?P<uuid>\d+)\)\s*$"
    MASTER_PATTERN = r"^\s*(?:(?P<cycle>\d+):\s*)?(?P<component>[\w-]+)(?:\s+(?P<action>[^:]+))?:\s*(?P<payload>.*?)\s*\(#(?P<uuid>\d+)\)\s*$"
    TOP_PATTERNS = {
        "lsu": re.compile(LSU_PATTERN),
        "cache_mem": re.compile(CACHE_MEM_PATERN),
        "pipeline": re.compile(PIPELINE_PATTERN),
        "master": re.compile(MASTER_PATTERN),   # < fallback pattern
    }

    match, pattern_name = None, None
    for key, pattern in TOP_PATTERNS.items():
        match = pattern.match(line)
        if match:
            pattern_name = key
            break
    if not match:
        return None
    # parsing identifiers
    component = match.group("component")
    component_parts = component.split("-", 3)
    if len(component_parts) != 4:
        return None
    cluster, socket, core, event = component_parts
    uuid = int(match.group("uuid"))
    # parsing payload
    action = match.group("action")
    payload = parse_payload(match.group("payload"))
    cycle_str = match.group("cycle")
    cycle = int(cycle_str) if cycle_str is not None else None

    # general payload parsing
    wid = parse_optional_int(payload.get("wid"))
    pc = parse_optional_int(payload.get("PC"))
    tmask = payload.get("tmask")
    if pattern_name == "pipeline":
        ex = payload.get("ex")
        op = payload.get("op")
        wb = parse_optional_int(payload.get("wb"))
        rd = parse_optional_int(payload.get("rd"))
        rs1_data_str = payload.get("rs1_data")
        rs2_data_str = payload.get("rs2_data")
        rs1_data = None if rs1_data_str is None else [parse_optional_int(v) for v in rs1_data_str]
        rs2_data = None if rs2_data_str is None else [parse_optional_int(v) for v in rs2_data_str]
        use_PC = parse_optional_int(payload.get("use_PC"))
        use_imm = parse_optional_int(payload.get("use_imm"))
        sop = parse_optional_int(payload.get("sop"))
        eop = parse_optional_int(payload.get("eop"))
    elif pattern_name == "lsu":
        addr = payload.get("addr")
        flags = payload.get("flags")
        byteen = parse_optional_int(payload.get("byteen"))
        data = payload.get("data")
        sop = parse_optional_int(payload.get("sop"))
        eop = parse_optional_int(payload.get("eop"))

    return TraceRecord(
        line_no=line_no,
        raw_line=line,
        cycle=cycle,
        cluster=cluster,
        socket=socket,
        core=core,
        wid=wid,
        uuid=uuid,
        pc=pc,
        tmask=tmask,
        event=event,
        action=action,
        pipeline_payload= {
            "ex": ex,
            "op": op,
            "wb": wb,
            "rd": rd,
            "rs1_data": rs1_data,
            "rs2_data": rs2_data,
            "use_PC": use_PC,
            "use_imm": use_imm,
            "sop": sop,
            "eop": eop,
        } if pattern_name == "pipeline" else None,
        lsu_payload={
            "addr": addr,
            "flags": flags,
            "byteen": byteen,
            "data": data,
            "sop": sop,
            "eop": eop,
        } if pattern_name == "lsu" else None,
        # other_payload=payload if pattern_name not in ("pipeline", "lsu") else None
        other_payload=payload # Keep the default payload
    )
