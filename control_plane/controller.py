import collections
import hashlib
import json
import argparse
import sys
import time
import threading

from client.RTEInterface import RTEInterface

THRIFT_API_LOCK = threading.Lock()


class PacketProcessor(object):
    class FuncThread(threading.Thread):
        def __init__(self, target, *args):
            self._target = target
            self._args = args
            threading.Thread.__init__(self)

        def run(self):
            self._target(*self._args)

    def __init__(self, args):
        RTEInterface.Connect(host=args.rpc_server, port=args.rpc_port, rpc='thrift', use_zlib=True)

        # grab all the digest info
        digests = RTEInterface.Digests.List()

        # a map for associating registration handle with digest data
        self.digest_map = collections.OrderedDict()

        # register for each digest
        for d in digests:
            print(d)
            # get the digest registration handle
            dh = RTEInterface.Digests.Register(d['id'])
            if dh < 0:
                sys.stderr.write("Failed to register for digest %s\n" % d.name)
                sys.exit(1)

            # associate the registration handle with the digest data
            self.digest_map[dh] = {'desc': d, 'count': 0}

    def __del__(self):
        RTEInterface.Disconnect()

    #    def __call__(self, msg):
    #        t1 = self.FuncThread(self.parse, msg)
    #        t1.daemon = True
    #        t1.start()

    def poll(self):

        print("polling for digests events")
        # okay now periodically retrieve and dump the digest data
        try:
            while 1:
                for digest_handle, digest_data in self.digest_map.items():
                    values = RTEInterface.Digests.Get(digest_handle)

                    if len(values) == 0:  # no data
                        continue

                    fldcnt = len(digest_data['desc']['fields'])
                    if len(values) % fldcnt != 0:
                        sys.stderr.write("Invalid field layout from digest %s" % digest_data['desc']['name'])
                        sys.exit(1)

                    for i in range(int(len(values) / fldcnt)):
                        dgflddata = {k['name']: int(v, 16)
                                     for k, v in
                                     zip(digest_data['desc']['fields'], values[fldcnt * i:fldcnt * (i + 1)])}
                        print(dgflddata)
                        self.debug_print(digest_data, dgflddata)

                        handler = getattr(self, 'on_' + digest_data['desc']['name'], None)
                        if handler:
                            handler(digest_data, dgflddata)

                    digest_data['count'] += 1

                time.sleep(0.1)

        except KeyboardInterrupt:  # exit on control-c
            pass

    def debug_print(self, dgdata, dgflddata):
        print("digest %s (P4 ID %d, P4 fieldlist %s)[%d] {" % (
            dgdata['desc']['name'],
            dgdata['desc']['app_id'],
            dgdata['desc']['field_list_name'],
            dgdata['count']))

        for flddesc, fielddata in dgflddata.items():
            print("    %s : 0x%x" % (flddesc, fielddata))
        print("}\n")

    def conn_to_table(self, src_addr, dst_addr, src_port, dst_port, protocol, seq_diff):
        tbl_id = "ingress::connections"
        priority = 1
        default_rule = False
        match = json.dumps({
            "ipv4.srcAddr": {
                "value": src_addr
            },
            "ipv4.dstAddr": {
                "value": dst_addr
            },
            "tcp.srcPort": {
                "value": src_port
            },
            "tcp.dstPort": {
                "value": dst_port
            },
            "ipv4.protocol": {
                "value": protocol
            }
        }).encode('utf-8')
        rule_name = "rule_" + str(hashlib.sha1(match).hexdigest())
        actions = json.dumps({
            "type": "ingress::saveDifferenceValue",
            "data": {
                "difference": {
                    "value": seq_diff
                }
            }
        }).encode('utf-8')
        timeout = None
        with THRIFT_API_LOCK:
            RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, priority, timeout)
        print("connection is added with diff:", str(seq_diff))

    def on__digest_learn_connection_t_1(self, dgdata, dgflddata):
        prefix = 'ingress::send_digest_connection::tmp_2.'
        self.conn_to_table(
            src_addr=dgflddata[prefix + 'srcAddr'],
            dst_addr=dgflddata[prefix + 'dstAddr'],
            src_port=dgflddata[prefix + 'srcPort'],
            dst_port=dgflddata[prefix + 'dstPort'],
            protocol=dgflddata[prefix + 'protocol'],
            seq_diff=dgflddata[prefix + 'seqDiff'])

        self.conn_to_table(
            src_addr=dgflddata[prefix + 'dstAddr'],
            dst_addr=dgflddata[prefix + 'srcAddr'],
            src_port=dgflddata[prefix + 'dstPort'],
            dst_port=dgflddata[prefix + 'srcPort'],
            protocol=dgflddata[prefix + 'protocol'],
            seq_diff=dgflddata[prefix + 'seqDiff_rev'])

        # self.ruleNum += 1
        print("Done Adding Rule")  # , self.ruleNum)
        print()


def main():
    parser = argparse.ArgumentParser(description='P4 Firewall-Controller config')
    parser.add_argument('-p', '--rpc-port', dest='rpc_port', default='20206', type=int,
                        help="Thrift RPC port (DEFAULT: 20206)")
    parser.add_argument('-s', '--rpc-server', dest='rpc_server', default='localhost', type=str,
                        help="Thrift RPC host (DEFAULT: localhost)")
    parser.add_argument('-t', '--rule-timeout', dest='rule_timeout', default=1000, type=float,
                        help="Rule Timeout - Rules will delete if not hit within t seconds (DEFAULT: 10 seconds)")

    args = parser.parse_args()

    pp = PacketProcessor(args)
    pp.poll()


if __name__ == '__main__':
    main()
