# Includes classes and code from Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Philippe Biondi <phil@secdev.org>

## includes modifications by ms@mwcollect.org

import re


class VolatileValue:
    def __repr__(self):
        return "<%s>" % self.__class__.__name__
    def __getattr__(self, attr):
        if attr == "__setstate__":
            raise AttributeError(attr)
        return getattr(self._fix(),attr)
    def _fix(self):
        return None

class Gen(object):
    def __iter__(self):
        return iter([])
    

class Net(Gen):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    ipaddress = re.compile(r"^(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)(/[0-3]?[0-9])?$")
    def __init__(self, net):
        self.repr=net

        tmp=net.split('/')+["32"]
        if not self.ipaddress.match(net):
            tmp[0]=socket.gethostbyname(tmp[0])
        netmask = int(tmp[1])

        def parse_digit(a,netmask):
            netmask = min(8,max(netmask,0))
            if a == "*":
                a = (0,256)
            elif a.find("-") >= 0:
                x,y = list(map(int,a.split("-")))
                if x > y:
                    y = x
                a = (x &  (0xff<<netmask) , max(y, (x | (0xff>>(8-netmask))))+1)
            else:
                a = (int(a) & (0xff<<netmask),(int(a) | (0xff>>(8-netmask)))+1)
            return a

        self.parsed = list(map(lambda x,y: parse_digit(x,y), tmp[0].split("."), list(map(lambda x,nm=netmask: x-nm, (8,16,24,32)))))
                                                                                               
    def __iter__(self):
        for d in range(*self.parsed[3]):
            for c in range(*self.parsed[2]):
                for b in range(*self.parsed[1]):
                    for a in range(*self.parsed[0]):
                        yield "%i.%i.%i.%i" % (a,b,c,d)
    def choice(self):
        ip = []
        for v in self.parsed:
            ip.append(str(random.randint(v[0],v[1]-1)))
        return ".".join(ip) 
                          
    def __repr__(self):
        return "Net(%r)" % self.repr


class SetGen(Gen):
    def __init__(self, set, _iterpacket=1):
        self._iterpacket=_iterpacket
        if type(set) is list:
            self.set = set
        elif isinstance(set, BasePacketList):
            self.set = list(set)
        else:
            self.set = [set]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.set:
            if (type(i) is tuple) and (len(i) == 2) and type(i[0]) is int and type(i[1]) is int:
                if  (i[0] <= i[1]):
                    j=i[0]
                    while j <= i[1]:
                        yield j
                        j += 1
            elif isinstance(i, Gen) and (self._iterpacket or not isinstance(i,BasePacket)):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %s>" % self.set.__repr__()

class BasePacket(Gen):
    pass

class BasePacketList:
    pass

def lhex(x):
    if type(x) in (int,int):
        return hex(x)
    elif type(x) is tuple:
        return "(%s)" % ", ".join(map(lhex, x))
    elif type(x) is list:
        return "[%s]" % ", ".join(map(lhex, x))
    else:
        return x

