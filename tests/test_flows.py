from conftest import ATTACKER, START_TIME, VICTIM, info, tcp_packet

from intrusionsense.flows import (
    ANALYZE_EVERY_N_PACKETS,
    IDLE_FLOW_TIMEOUT_SECONDS,
    MAX_FLOW_DURATION_SECONDS,
    FlowEvent,
    FlowTable,
)


def test_reply_packets_join_the_initiators_flow():
    table = FlowTable()
    table.add_packet(info(tcp_packet(flags="S")))
    table.add_packet(
        info(tcp_packet(src=VICTIM, dst=ATTACKER, sport=80, dport=40000, flags="SA", at=START_TIME + 0.01))
    )

    assert len(table) == 1
    [report] = table.close_all()
    assert report.flow.key == (ATTACKER, VICTIM, 40000, 80, 6)
    assert len(report.flow.fwd_lengths) == 1 and len(report.flow.bwd_lengths) == 1


def test_fin_closes_the_flow_and_reports_it():
    table = FlowTable()
    table.add_packet(info(tcp_packet(flags="S")))
    [report] = table.add_packet(info(tcp_packet(flags="FA", at=START_TIME + 1)))

    assert report.event is FlowEvent.FINISHED
    assert len(table) == 0


def test_single_packet_flows_are_dropped_not_reported():
    table = FlowTable()
    table.add_packet(info(tcp_packet(flags="S")))

    assert table.expire_idle(START_TIME + IDLE_FLOW_TIMEOUT_SECONDS + 1) == []
    assert len(table) == 0


def test_idle_flows_time_out():
    table = FlowTable()
    table.add_packet(info(tcp_packet(flags="S")))
    table.add_packet(info(tcp_packet(flags="A", at=START_TIME + 0.1)))

    assert table.expire_idle(START_TIME + IDLE_FLOW_TIMEOUT_SECONDS) == []
    [report] = table.expire_idle(START_TIME + IDLE_FLOW_TIMEOUT_SECONDS + 1)
    assert report.event is FlowEvent.TIMEOUT


def test_long_flows_report_midway_and_keep_running():
    table = FlowTable()
    reports = []
    for i in range(ANALYZE_EVERY_N_PACKETS):
        reports += table.add_packet(info(tcp_packet(flags="A", at=START_TIME + i * 0.01)))

    assert [r.event for r in reports] == [FlowEvent.UPDATE]
    assert len(table) == 1


def test_flows_longer_than_max_duration_are_cut():
    table = FlowTable()
    table.add_packet(info(tcp_packet(flags="S")))
    table.add_packet(info(tcp_packet(flags="A", at=START_TIME + 1)))
    [report] = table.add_packet(info(tcp_packet(flags="A", at=START_TIME + MAX_FLOW_DURATION_SECONDS + 2)))

    assert report.event is FlowEvent.TIMEOUT
    assert len(table) == 1  # the late packet started a new flow


def test_full_table_evicts_the_least_recently_seen_flow():
    table = FlowTable(max_flows=2)
    for port in (1001, 1002):
        table.add_packet(info(tcp_packet(sport=port, flags="S")))
        table.add_packet(info(tcp_packet(sport=port, flags="A", at=START_TIME + 0.1)))
    table.add_packet(info(tcp_packet(sport=1001, flags="A", at=START_TIME + 0.2)))  # 1001 now most recent

    [evicted] = table.add_packet(info(tcp_packet(sport=1003, flags="S", at=START_TIME + 0.3)))

    assert evicted.flow.key[2] == 1002
    assert len(table) == 2


def test_new_flow_callback_sees_every_new_flow():
    started = []
    table = FlowTable(on_new_flow=lambda key, at: started.append(key[2]))
    for port in (1, 2, 3):
        table.add_packet(info(tcp_packet(sport=port)))

    assert started == [1, 2, 3]
