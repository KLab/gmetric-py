#!/usr/bin/env python3
""" This module is for sending metric to Ganglia.

example1 normal metric:
s = Sender('127.0.0.1')
g = Gmetric()
g.gv_name = 'temperature'
g.gv_type = TypeEnum.INT8
g.gv_value = '28'
g.gv_units = 'Celsius'
g.gv_slope = SlopeEnum.BOTH
g.gv_tmax = 30
g.gv_dmax = 360
s.create_socket()
s.send(g)
s.close_socket()

example2: multiple metric:
s = Sender('127.0.0.1')
s.create_socket()
gtemp = Gmetric()
gtemp.gv_name = 'temperature'
gtemp.gv_type = TypeEnum.INT8
gtemp.gv_value = '28'
gtemp.gv_units = 'Celsius'
gtemp.gv_slope = SlopeEnum.BOTH
gtemp.gv_tmax = 30
gtemp.gv_dmax = 360
s.send(gtemp)
gvol = Gmetric()
gvol.gv_name = 'voltage'
gvol.gv_type = TypeEnum.INT16
gvol.gv_value = '220'
gvol.gv_units = 'Voltage'
gvol.gv_slope = SlopeEnum.BOTH
svol.gv_tmax = 30
svol.gv_dmax = 120
s.send(gvol)
s.close_socket()

example3: spoof heatbeat:
s = Sender('127.0.0.1')
g = Gmetric()
g.set_heartbeat()
g.gm_spoof_host = '192.168.0.1:myswitch'
s.create_socket()
s.send(g)
s.close_socket()
"""

import logging
import socket
import ipaddress
import threading
from enum import Enum, IntEnum, unique
import xdrlib

__all__ = ['Gmetric', 'TypeEnum', 'SlopeEnum', 'Sender']


@unique
class TypeEnum(Enum):
    """ Enumerate value of gmetric type """
    STRING = 'string'
    INT8 = 'int8'
    UINT8 = 'uint8'
    INT16 = 'int16'
    UINT16 = 'uint16'
    INT32 = 'int32'
    UINT32 = 'uint32'
    FLOAT = 'float'
    DOUBLE = 'double'

    @staticmethod
    def from_str(strval):
        """Returns TypeEnum value which fit argument"""
        for etype in list(TypeEnum):
            if strval == etype.value:
                return etype
        raise ValueError('unsupported Type: %s' % strval)


@unique
class SlopeEnum(IntEnum):
    """ Enumerate value of gmetric slope """
    ZERO = 0
    POSITIVE = 1
    NEGATIVE = 2
    BOTH = 3
    UNSPECIFIED = 4
    DERIVATIVE = 5

    @staticmethod
    def from_str(strval):
        """Returns SlopeEnum value which fit argument"""
        ustrval = strval.upper()
        for slope in list(SlopeEnum):
            if slope.name == ustrval:
                return slope
        raise ValueError('unsupported Slope: %s' % strval)


class Gmetric:
    """ instance of hold gmetric value.
    instance variables starts with 'gv_' must be set (except spoofheartbeat).
    variables:
        gv_name:    metric name
                        (var type: str)
        gv_value:   metric value
                        (var type: str)
        gv_type:    metric type
                        (var type: TypeEnum)
        gv_units:   metric unit of measure for the value
                        (var type: str)
        gv_slope:   metric slope
                        (var type: SlopeEnum)
        gv_tmax:    maxtime in secs between gmetric calls
                        (var type: unsigned int)
        gv_dmax:    lifetime in secs this metric
                        (var type: unsigned int)
        gm_cluster: metric cluster
                        (var type: str)
        gm_group:   group of metric
                        (var type: list or tuple)
        gm_desc:    description of metric
                        (var type: str)
        gm_title:   title of metric
                        (var type: str)
        gm_spoof_host: for spoofing, spoofing host information
                           (var type: str, format: 'ipaddr:host')
        gm_spoof_heartbeat: this metric is/isnot spoof-heartbeat
                           (var type: bool)"""
    def __init__(self):
        self.__myhost = str(socket.gethostname())
        self.__mylock = threading.RLock()
        self.gv_name = ''
        self.gv_value = ''
        self.gv_type = TypeEnum.STRING
        self.gv_units = ''
        self.gv_slope = SlopeEnum.BOTH
        self.gv_tmax = 60
        self.gv_dmax = 0
        self.gm_cluster = None
        self.gm_group = None
        self.gm_desc = None
        self.gm_title = None
        self.gm_spoof_host = None
        self.gm_spoof_heartbeat = False

    def __setattr__(self, name, value):
        if name.startswith('gv_'):
            Gmetric.__check_gv_var__(name.replace('gv_', '', 1), value)
        elif name.startswith('gm_'):
            Gmetric.__check_gm_var__(name.replace('gm_', '', 1), value)
        logging.debug('__setattr__: %s, %s', name, value)
        super(Gmetric, self).__setattr__(name, value)

    @staticmethod
    def __check_containing_quot__(value):
        return value and '"' in value

    @staticmethod
    def __check_gv_var__(gvname, value):
        if gvname in ('name', 'value', 'units'):
            if not isinstance(value, str):
                raise ValueError('')
            if Gmetric.__check_containing_quot__(value):
                raise ValueError('')
        elif gvname == 'type':
            if value not in TypeEnum:
                raise ValueError('')
        elif gvname == 'slope':
            if value not in SlopeEnum:
                raise ValueError('')
        elif gvname in ('tmax', 'dmax'):
            if int(value) < 0:
                raise ValueError('')

    @staticmethod
    def __check_gm_var__(gmname, value):
        if gmname in ('cluster', 'desc', 'title'):
            if value is not None and not isinstance(value, str):
                raise ValueError('')
            if value and Gmetric.__check_containing_quot__(value):
                raise ValueError('')
        elif gmname == 'group':
            if value is not None:
                if not (isinstance(value, list) or isinstance(value, tuple)):
                    raise ValueError('')
                for grpval in value:
                    if Gmetric.__check_containing_quot__(grpval):
                        raise ValueError('')
        elif gmname == 'spoof_host':
            if value and Gmetric.__validate_spoof_host__(value):
                raise ValueError('')
        elif gmname == 'spoof_heartbeat':
            if not isinstance(value, bool):
                raise ValueError('')

    @staticmethod
    def __validate_spoof_host__(value):
        if ':' not in value:
            return False
        (spoofip, spoofhost) = value.split(':', 1)
        if len(spoofip) == 0 or len(spoofhost) == 0:
            return False

    def set_heartbeat(self):
        """ set to used to for spoof heartbeat """
        self.gv_name = 'heartbeat'
        self.gv_type = TypeEnum.UINT32
        self.gv_value = '0'
        self.gv_units = ''
        self.gv_slope = SlopeEnum.ZERO
        self.gv_tmax = 0
        self.gv_dmax = 0
        self.gm_spoof_heartbeat = True

    def get_metabuf(self):
        """ return xdr's string for gmetric metadata. """
        mpack = xdrlib.Packer()
        mpack.pack_int(128)
        self.__mylock.acquire()
        try:
            targethost = self.__myhost
            if self.gm_spoof_host:
                targethost = self.gm_spoof_host
            mpack.pack_string(targethost.encode())
            self.__get_meta_value_buf__(mpack)
            self.__get_meta_meta_buf__(mpack)
        finally:
            self.__mylock.release()
        return mpack.get_buffer()

    def __get_meta_value_buf__(self, pack):
        if self.gm_spoof_heartbeat:
            pack.pack_string(b'heartbeat')
        else:
            pack.pack_string(self.gv_name.encode())
        pack.pack_bool(self.gm_spoof_host and len(self.gm_spoof_host) > 0)
        pack.pack_string(self.gv_type.value.encode())
        if self.gm_spoof_heartbeat:
            pack.pack_string(b'heartbeat')
        else:
            pack.pack_string(self.gv_name.encode())
        pack.pack_string(self.gv_units.encode())
        pack.pack_uint(self.gv_slope.value)
        pack.pack_uint(self.gv_tmax)
        pack.pack_uint(self.gv_dmax)

    def __get_meta_meta_buf__(self, pack):
        mlen = 0
        for gmelement in (self.gm_cluster, self.gm_desc,
                          self.gm_title, self.gm_spoof_host):
            if gmelement is not None:
                mlen += 1
        if self.gm_group:
            mlen += len(self.gm_group)
        if self.gm_spoof_heartbeat:
            mlen += 1
        pack.pack_uint(mlen)
        if self.gm_cluster:
            pack.pack_string(b'CLUSTER')
            pack.pack_string(self.gm_cluster.encode())
        if self.gm_desc:
            pack.pack_string(b'DESC')
            pack.pack_string(self.gm_desc.encode())
        if self.gm_title:
            pack.pack_string(b'TITLE')
            pack.pack_string(self.gm_title.encode())
        if self.gm_group:
            for gmgelement in self.gm_group:
                pack.pack_string(b'GROUP')
                pack.pack_string(gmgelement.encode())
        if self.gm_spoof_host:
            pack.pack_string(b'SPOOF_HOST')
            pack.pack_string(self.gm_spoof_host.encode())
        if self.gm_spoof_heartbeat:
            pack.pack_string(b'SPOOF_HEARTBEAT')
            pack.pack_string(b'yes')

    def get_valuebuf(self):
        """ return xdr's string for gmetric value. """
        pack = xdrlib.Packer()
        pack.pack_int(128 + 5)
        self.__mylock.acquire()
        try:
            targethost = self.__myhost
            if self.gm_spoof_host:
                targethost = self.gm_spoof_host
            pack.pack_string(targethost.encode())
            if self.gm_spoof_heartbeat:
                pack.pack_string(b'heartbeat')
            else:
                pack.pack_string(self.gv_name.encode())
            pack.pack_bool(self.gm_spoof_host and len(self.gm_spoof_host) > 0)
            pack.pack_string(b'%s')
            pack.pack_string(str(self.gv_value).encode())
        finally:
            self.__mylock.release()
        return pack.get_buffer()


class Sender:
    """ instance of metric sender """
    def __init__(self, dsthost='127.0.0.1', dstport=8649, ttl=1):
        super(Sender, self).__init__()
        if dstport <= 0 or dstport >= 65536:
            raise ValueError('')
        self.__dstaddr = (socket.gethostbyname(dsthost), dstport)
        self.__ttl = ttl
        self.__mysocket = None
        self.__mylock = threading.RLock()

    def create_socket(self):
        """ create sender socket"""
        self.__mysocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if ipaddress.ip_address(self.__dstaddr[0]).is_multicast:
            self.__mysocket.setsockopt(socket.IPPROTO_IP,
                                       socket.IP_MULTICAST_TTL, self.__ttl)

    def send(self, metric):
        """ send metric """
        if not isinstance(metric, Gmetric):
            raise ValueError('')
        if metric.gm_spoof_heartbeat and not metric.gm_spoof_host:
            raise ValueError('spoof-heatbeat needs spoof-host')
        self.__mylock.acquire()
        try:
            mbuf = metric.get_metabuf()
            vbuf = metric.get_valuebuf()
        finally:
            self.__mylock.release()
        logging.debug("=== metadata ===\n%s", mbuf)
        logging.debug("=== value ===\n%s", vbuf)
        if not self.__mysocket:
            self.create_socket()
        self.__mysocket.sendto(mbuf, self.__dstaddr)
        self.__mysocket.sendto(vbuf, self.__dstaddr)

    def close_socket(self):
        """ close sender socket """
        try:
            if self.__mysocket:
                self.__mysocket.close()
        finally:
            self.__mysocket = None

    def __del__(self):
        try:
            self.close_socket()
        except socket.error:
            pass


if __name__ == '__main__':
    import argparse

    def gmetricgroups(value):
        """ group(comma separted string) to list """
        return value.split(',')

    def gmetricspoof(value):
        """ check spoof host capable string """
        if value and ':' not in value:
            raise argparse.ArgumentTypeError('must be colon-separated value')
        return value

    def debugopts(parser):
        """ append debug option group to parser """
        pgroup = parser.add_argument_group('debug parameter')
        pgroup.add_argument('-X', '--debug',
                            dest='debug', action='store_true',
                            help='need to debug')

    def heartbeatopts(parser, req=False):
        """ append spoof-heartbeat option group to parser """
        pgroup = parser.add_argument_group('heartbeat parameter')
        pgroup.add_argument('-H', '--heartbeat',
                            dest='heartbeat', action='store_true',
                            required=req,
                            help=('spoof a heartbeat message '
                                  '(use with spoof option)'))

    def normalopts(parser, req=False):
        """ append normal metric option group to parser """
        pgroup = parser.add_argument_group('sending parameter')
        pgroup.add_argument('-n', '--name',
                            dest='name', type=str, required=req,
                            help='Name of the metric')
        pgroup.add_argument('-v', '--value',
                            dest='value', type=str, required=req,
                            help='Value of the metric')
        typechoices = []
        for etype in list(TypeEnum):
            typechoices.append(etype.value)
        pgroup.add_argument('-t', '--type',
                            dest='vtype', type=str, required=req,
                            choices=tuple(typechoices),
                            help='Value Type of the metric')
        pgroup.add_argument('-u', '--units',
                            dest='units', type=str, default='',
                            help=('Unit of measure for the value '
                                  'e.g. Kilobytes, Celcius '
                                  '(default="%(default)s")'))
        slopechoices = []
        for slope in (SlopeEnum.ZERO, SlopeEnum.POSITIVE,
                      SlopeEnum.NEGATIVE, SlopeEnum.BOTH):
            slopechoices.append(slope.name.lower())
        pgroup.add_argument('-s', '--slope',
                            dest='slope', type=str, default='both',
                            choices=tuple(slopechoices),
                            help='(default="%(default)s")')
        pgroup.add_argument('-x', '--tmax',
                            dest='tmax', type=int, default=60,
                            help=('The maximum time in seconds '
                                  ' between gmetric calls '
                                  '(default=%(default)d)'))
        pgroup.add_argument('-d', '--dmax',
                            dest='dmax', type=int, default=0,
                            help=('The lifetime '
                                  'in seconds of this metric '
                                  '(default=%(default)d)'))

    def metaopts(parser, req=False):
        """ append metric metadata option group to parser """
        pgroup = parser.add_argument_group('metadata')
        pgroup.add_argument('-S', '--spoof',
                            dest='spoof', type=gmetricspoof, required=req,
                            help=('IP address and name of '
                                  'host/device (colon separated) '
                                  'we are spoofing'))
        pgroup.add_argument('-g', '--group',
                            dest='group', type=gmetricgroups, default=[],
                            help='Group(s) of the metric (comma-separated)')
        pgroup.add_argument('-C', '--cluster',
                            dest='cluster', type=str,
                            help='Cluster of the metric')
        pgroup.add_argument('-D', '--desc',
                            dest='desc', type=str,
                            help='Description of the metric')
        pgroup.add_argument('-T', '--title',
                            dest='title', type=str,
                            help='Title of the metric')

    def destopts(parser):
        """ append metric destination option group to parser """
        pgroup = parser.add_argument_group('connection string')
        pgroup.add_argument('destaddr', metavar='destination-address',
                            type=str, default='127.0.0.1', nargs='?',
                            help='send to address (default=%(default)s)')
        pgroup.add_argument('destport', metavar='destination-port', nargs='?',
                            type=int, default=8649, choices=range(1, 65535),
                            help='send to port (default=%(default)d)')
        pgroup.add_argument('mcastttl', metavar='multicast-ttl', nargs='?',
                            type=int, default=1, choices=range(1, 20),
                            help=('ttl for multicast addressse '
                                  '(default=%(default)d)'))

    def main():
        """ send single metric """
        hbparser = argparse.ArgumentParser(add_help=False)
        heartbeatopts(hbparser)
        (hbns, _) = hbparser.parse_known_args()
        rparser = argparse.ArgumentParser()
        heartbeatopts(rparser, hbns.heartbeat)
        normalopts(rparser, not hbns.heartbeat)
        metaopts(rparser, hbns.heartbeat)
        destopts(rparser)
        debugopts(rparser)
        ropts = rparser.parse_args()

        if ropts.debug:
            logging.basicConfig(level=logging.DEBUG)
        gmtrc = Gmetric()
        if hbns.heartbeat:
            gmtrc.set_heartbeat()
        else:
            gmtrc.gv_name = ropts.name
            gmtrc.gv_type = TypeEnum.from_str(ropts.vtype)
            gmtrc.gv_value = ropts.value
            gmtrc.gv_units = ropts.units
            gmtrc.gv_slope = SlopeEnum.from_str(ropts.slope)
            gmtrc.gv_tmax = ropts.tmax
            gmtrc.gv_dmax = ropts.dmax
        if ropts.cluster and len(ropts.cluster) > 0:
            gmtrc.gm_cluster = ropts.cluster
        if ropts.group and len(ropts.group) > 0:
            gmtrc.gm_group = ropts.group
        if ropts.title and len(ropts.title) > 0:
            gmtrc.gm_title = ropts.title
        if ropts.spoof and len(ropts.spoof) > 0:
            gmtrc.gm_spoof_host = ropts.spoof
        gmtrc.gm_spoof_heartbeat = hbns.heartbeat
        sender = Sender(ropts.destaddr, ropts.destport, ropts.mcastttl)
        try:
            sender.create_socket()
            sender.send(gmtrc)
        finally:
            sender.close_socket()
        exit(0)

    main()
