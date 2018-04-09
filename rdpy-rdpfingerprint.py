#!/usr/bin/env python
#
# rdpy-rdpfingerprint.py -- Modified version of rdpy-rdpscreenshot.py which
#                        -- adds ssdeep hashing capabilities to make a guess
#                        -- of which operating system a host is running.
#
# by Daniel Roberson @dmfroberson                               January/2018
#
# TODO:
#  - Notify if screen is just a solid color somehow (happens a lot when
#    slower/embedded devices haven't ran RDP in a while)
#  - 
#
# Here is the original header:
#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
example of use rdpy
take screenshot of login page
"""

import sys, getopt
import ssdeep

from PyQt4 import QtCore, QtGui
from rdpy.protocol.rdp import rdp
from rdpy.ui.qt4 import RDPBitmapToQtImage
import rdpy.core.log as log
from rdpy.core.error import RDPSecurityNegoFail
from twisted.internet import task

#set log level
log._LOG_LEVEL = log.Level.NONE

hashes = {
    # Windows 7 Enterprise
    "192:W/TkUOZIxnGYtnlztnHd6fNd5XzvZOybIGNzuxOIpDK8S1AzI:UBOZmGYfzd96vOiHGK8U" : "Windows 7 Enterprise",
    "192:W/Tk6ORryY0kMjU0D/G49T8UWUNXrl84LDRARGYT7bcUyMyLOZz:UY6ORryYvKHD+o8A2wADTfcUyM6Ot" : "Windows 7 Enterprise",
    "384:UTR+U6c/5CJcL9shJsR1Tgr9sARpRnlAILOiHGK8U:UTRD/2Lr9lt7mK8U" : "Windows 7 Enterprise",
    "384:UM+mdpdsAWPwAbmBPZLlcDBY+HOcLNQuxbOif0z:UMnHdWPwAbWPoD9RmwOifW" : "Windows 7 Enterprise",
    "192:W/LTKfZMryUPTnFp15Sdj32fYVTgzzb1A:UwMxXSdj32ITgzPi -- See s-172.16.17.60.jpg" : "Windows 7 Enterprise",
    "192:W/TkUOZIxniicLLKadDE9T7mG0yEYsoFp15SdhqyfrMOk0bM:UBOZmiiQWJ9eG0y8gXSdhHfrMOkD" : "Windows 7 Enterprise",
    "384:U2KgnTGn+Rivf85jncrTIZnNVWAY9MRUn+Qq:U2RnG2crTIvV5vT" : "Windows 7 Enterprise",
    "768:Ulq3cKSKoCxPkmCOKfcelvDpEEyUgK8K8K8AwOu:UlIcGoXm7ecAgK8K8K8n" : "Windows 7 Enterprise",
    "768:UUrrrJKbFNy2w63NlE6hs19L8wNaMCNjHRvT:UaKhNy2wCNCZ9Lf4TNHN" : "Windows 7 Enterprise",
    "768:Uxa/5ygty8VuoO+4hQNkjRR5inZ8yMQEDgNtnBG2awOu:UDt8VuoO+nA5sHMQjNtnJ" : "Windows 7 Enterprise",
    "384:UCugOGRZhmbQls4hmiXljHGxD9ewoxGK8U:UCjOG3KQ24fFsxK8U" : "Windows 7 Enterprise",

    # Windows 7 Professional
    "384:UBOZSiM+VGkt66pLvg8sK9OufOXALNdTRxNab:UkZSxIrY6RY8sKfzfNc" : "Windows 7 Professional",
    "1536:UinrqepA0Xrcpw6OKq9nOnOWPwGpppZyI:beeZcO6dI+OWwM" : "Windows 7 Professional",
    "384:UM+mdpdsAWPwAdTTTTOQpppVruWXpF/OMaq3Qd+aY:UMnHdWPwAMQpppZHkqAdI" : "Windows 7 Professional",
    "384:UM+mdpdsAW5DdLgmbQ914hrieIXOryNwDSfHnkqu7aS1:UMnHdWpdRWuheeqOrnSfnfuv" : "Windows 7 Professional",
    "1536:UZtK+VC7tadpBwsmyCFZTe2y9wbkXB4O+hYA6g:57t+BKBRb57T" : "Windows 7 Professional",
    "384:UKV7CIpJPvvVKP5MQZytZRCJpHG/4ebdZaxtlq:UTI3vvVKP5MeSLCJpH24udkHg" : "Windows 7 Professional",

    # Windows 7 Ultimate
    "384:UbPoedvlaD/0xgaVh7XGDtR5RGAJGlaho:UZUACaVhTEhR5Jpo" : "Windows 7 Ultimate",
    "384:UbPoymWNxCILmog6bopp+LTysgfUKHAHwo:Ugk2X6bopo1g5AQo" : "Windows 7 Ultimate",

    # Windows 7 Embedded Standard
    "384:UBcRt9SuXJPralJ5a/2gzjOmpvN6O3lZWcea6:UkKEzjfpvNfZWZa6" : "Windows 7 Embedded Standard",
    "192:W/TkUOc41dzikFw/K9QqZAsZn1ZQA8C8/vceqa7ezBjJA:UBOc4mV/K9nZAU1ZWcea6" : "Windows 7 Enbedded Standard",

    # Windows Embedded
    "24:49YMW10o0XxDuLHeOWXG4OZ7DAJuLHenX3+:49YMAFuERA4" : "Windows Embedded Standard",

    # Windows Server 2003 Standard
    "384:UEoYb6LNdmS7Jhhmp7IWOYg0DwSSZKaxjyESbaVhnE/gMJGZ:UEoYb6hd5j8ZFZZexWEhnE/gMJGZ" : "Windows Server 2003 Standard Edition",
    "384:UEoYb6LNdmS7Jhhmp7IWOYg0DwSSZKa7kzfpVDaY9jHvJc66c:UEoYb6hd5j8ZFZZeIdF9jJc66c" : "Windows Server 2003 Standard Edition",
    "384:UEoYb6LNdmS7Jhhmp7IWOYg0DwSSZKafjCp/q9s8w7JXq+:UEoYb6hd5j8ZFZZe7aq9s/7JXq+" : "Windows Server 2003 Standard Edition",

    # Windows Server 2003 R2 Standard
    "384:UbXEwMsQ1HocX6g+0B+DtvPPf000mSjGeTqgFa:UbXI71rItxmG4qka" : "Windows Server 2003 R2 Standard Edition",
    "384:UbXEwMsQ1HocX6g+0B+Dtvx000mSjGeTqgFa:UbXI71rIhmG4qka" : "Windows Server 2003 R2 Standard Edition",

    # Windows Server 2003 R2 Enterprise
    "384:Ubs3S2GItvR8xYABuFQmItSFzR4UNUTSzPw0S7qZvj000mSjGeTqgFa:Ubb235RsYAQOt5TEw0mqZvFmG4qka" : "Windows Server 2003 R2 Enterprise Edition",
    "768:UX6OIUQeUP2qwwlklOxx2oqoEvT9WLn6iIjSW:UX6OIac9lklYWT96dIjf" : "Windows Server 2003 R2 Enterprise Edition",
    "384:Ubs3S2GItvR8xYABuFQmItSFzR4UNUTSzPw0S5eWchhhVd/WwJupyppppppg:Ubb235RsYAQOt5TEw03zUx" : "Windows Server 2003 R2 Enterprise Edition",
    "768:UXTuqHISuH0Dlu1EXldmh5HYP6QVL7qUGkpXAWOx+sfrd:UXy0wylueXldI4P6QVPq/kpXhOXd" : "Windows Server 2003 R2 Enterprise Edition",

    # Windows Server 2008 Standard
    "384:UqAA+/IL79c/JJJJOVsrHTduHyTOfMfOC99Q24yuUmnkl5dyg:UqAN/IX6WVsrHORS3buXne5dyg" : "Windows Server 2008 Standard",
    "192:W/poIGaioxzLUwg5m9gD7dORyMWo8aXMXYIbDWH0MvIn7:Upo+x/UB5mK7dO7DXMIoSH0MvI7" : "Windows Server 2008 Standard",
    "384:UnoeKmMRNOAdrVtRfxIGmHQ+9y37GUmnkl5dyg:UjKVRNDXxVmwZLGXne5dyg" : "Windows Server 2008 Standard",
    "384:UnoeKmMRNOA90+KdsfgFFcNxH7asEex0FistO:UjKVRND9wL62HFXO" : "Windows Server 2008 Standard",
    "192:W/nKneKmMrhDyaODEfKnJrPy4hpDYoM+vJz5X0xRywq8zi/94407byF3:UnoeKmMRNOASnJnTDYovJYQwq8zKomp" : "Windows Server 2008 Standard",

    # Windows Server 2008 Enterprise
    "384:UnoeKmMRNOASw/QVsjnKYL+qqOiV9UeLYcAfmrG7:UjKVRNDSwksjKYLvveLYzb7" : "Windows Server 2008 Enterprise",

    # Windows Server 2008 R2 Standard
    "192:W/QYC/XxamdUSF5MHqxifn2SyEEchNN27xFrKpkxALbxzottCxQi2Ls086573:UBKamrFyHqxWEchW7xFrKpDLFpxgBd" : "Windows Server 2008 R2 Standard",
    "384:UBKaYtrtx9CM6WDeCOSnXMsPIksMK0HhkM:UBKT3Z6WDbncsPIksV0H6M" : "Windows Server 2008 R2 Standard",
    "192:W/B9RDbu88Kn8dHhCIyfJJuUWR/6OrJzR+nZXnyHHxXuZII57js:UBT/uKnahClxmRJ+ZXGq7I" : "Windows Server 2008 R2 Standard",
    "192:W/B9RDbu88Kn8ddh4G3Z7JnungLCMHgdjSypXXfW7HvSHmI:UBT/uKnS1J7ypXXfW7HvSHmI" : "Windows Server 2008 R2 Standard",
    "384:UBT/uKncTEMc1PjODG4yyfod0YARJJVrng7:UV/uwcTdcJODyyfrJJJZ4" : "Windows Server 2008 R2 Standard",
    "192:W/B9RDbu88Kn8dthCIp210+3vwUxnungLCMHgdjSypXXfW7HvSHmI:UBT/uKnUhCYqF7ypXXfW7HvSHmI" : "Windows Server 2008 R2 Standard",
    "384:UBT/uKnbP22RoDqRAkglypubypXXfW7HvSHmI:UV/uwS24qRAkTxKqD" : "Windows Server 2008 R2 Standard",
    "192:W/B9RDbu88Kn8dPTZNo93M2dqvSIxW9WyTA2iMoMkPrUAkh4d0W23GX5QEmoHhkM:UBT/uKnQo1YSIxzyTARMsPIksMK0HhkM" : "Windows Server 2008 R2 Standard",
    "192:W/QYC/XxamdUSF5MHqxifRpXSL5w1Fef7WCn8zvS1imGz9IB8:UBKamrFyHqxuULFzd8DgW9Ia" : "Windows Server 2008 R2 Standard",

    # Windows Server 2008 R2 Enterprise
    "384:UBT/uKnWP5FX2RJ+4AVFO6Cpe0fgirbDqTb:UV/uwWPmf+4ArO6CPgi2/" : "Windows Server 2008 R2 Enterprise",
    "384:UBT/uKn/6SXHsnafRJ+4AVFO6Cpe0fgirbDqTb:UV/uwiUHqUf+4ArO6CPgi2/" : "Windows Server 2008 R2 Enterprise",
    "384:UBT/uKnbP22RoDqRAkglypu4TS5ApUk87Xc:UV/uwS24qRAkhTnpIjc" : "Windows Server 2008 R2 Enterprise",
    "384:UM+mdpdsAW5DdFYkkkkakywWngpppQsdeG0WM6SFwTS5ApUk87Xc:UMnHdWpdFx7wWngpppnsNWM6IwTnpIjc" : "Windows Server 2008 R2 Enterprise",
    "192:W/B9RDbu88Kn8dthCIp210+3vwUxnungLCMHgdRTWLTV5FSrvXxYeokzbxm710yc:UBT/uKnUhCYqFYTS5ApUk87Xc" : "Windows Server 2008 R2 Enterprise",
    "192:W/N2B1P0j6wO0n8E/FuJGtwl09CWJ2F+X3ZGTyoORwzXPU0UCVt3UNrEg2:UQBtwO0n8E/WQ7JYiiyoOuc0UCVGBx2" : "Windows Server 2008 R2 Enterprise",

    # XP Professional
    "384:UVolJ09AQ9EST4t1rImMbyo8uY77EV1JE7IpOb2GfRLdirwaStzS7OON:UOJTQ9EGSp4bymV47Ipo2GJRirwaSt+L" : "Windows XP Professional",
    "768:UOJTQ9E9WQWDCZJ8Nu7WF4V49Z55vsVgVfVfVfDJu:UOFtWNDCPJ655vsVUu" : "Windows XP Professional",
    "384:UEgOWL7vCoQCPm2ONqwkXxhUy8Y0+mxikEIDwBul1oJ+U638:UFfXqVCOvqwkXjUy8gmxikZkuuLj" : "Windows XP Professional",
    "1536:Ufw15rvwudQf4e7OFCpoSqe3vpp/Ze94F/55fR6Rc/L0Jz1kAXAHn4EGujpVgTlE:6wLsueECpoYRpwyORcjif2n4EGjZZmlf" : "Windows XP Professional w/ bad ass grass and sky background",
    "1536:Ufw15rvwudQQWh2L6WA4iE/GVOaQTg79h0BN8in0zWkYm8anK:6wLsueQWc+WA41GcZvB+in3kYm8aK" : "Windows XP Professional w/ bad ass grass and sky background",
    "768:U8nIBz6wCtfdrhEme4VP8555fnXXX9HjXk4QKbhKbP9EZQXNA6r6wZ:U8nOmwYfdL3I55djXhKLPeY" : "Windows XP Professional",
    "768:U5EwmiPf7V1ofYekd/XUPDTr4+ovTZAo7XHxwY:U5pmmfXo5uPeDTE+tGh" : "Windows XP Professional",
    "384:UVb1UDUwpBwCH27VisjftCMYezp4ReKHCP3eeeeev:U5EwmiPf7V9y" : "Windows XP Professional",
    "768:UZJ1etXyVmmxvdrRRilB4vTVVVVVVVVVVVVVG/RNtCd:UZJktizxFE35NtCd" : "Windows XP Professional",
    "384:UVMgOW0UVzjkLWm2ONOIv0pCQEqQ7vO0jB/5gzyP4QuzhXV40k:UXffjkL3vlv7gQ7vO0jB+zOchXVe" : "Windows XP Professional",
}

def check_ssdeep_hash(path):
    high_score = 0
    high_score_target = ""
    global hashes

    try:
        fuzzy_hash = ssdeep.hash_from_file(path)
    except IOError:
        fuzzy_hash = "Permission Denied"
    except UnicodeDecodeError:
        fuzzy_hash = "Unicode Decode Error"

    for candidate, target in hashes.iteritems():
        score =  ssdeep.compare(fuzzy_hash, candidate)
        if score > high_score:
            high_score = score
            high_score_target = target

    if high_score > 0:
        print "Best match: %s -- %s%%" % (high_score_target, high_score)
        print "Hash: %s" % fuzzy_hash
    else:
        print "No matches for hash %s -- See %s" % (fuzzy_hash, path)

class RDPScreenShotFactory(rdp.ClientFactory):
    """
    @summary: Factory for screenshot exemple
    """
    __INSTANCE__ = 0
    __STATE__ = []
    def __init__(self, reactor, app, width, height, path, timeout):
        """
        @param reactor: twisted reactor
        @param width: {integer} width of screen
        @param height: {integer} height of screen
        @param path: {str} path of output screenshot
        @param timeout: {float} close connection after timeout s without any updating
        """
        RDPScreenShotFactory.__INSTANCE__ += 1
        self._reactor = reactor
        self._app = app
        self._width = width
        self._height = height
        self._path = path
        self._timeout = timeout
        #NLA server can't be screenshooting
        self._security = rdp.SecurityLevel.RDP_LEVEL_SSL
        
    def clientConnectionLost(self, connector, reason):
        """
        @summary: Connection lost event
        @param connector: twisted connector use for rdp connection (use reconnect to restart connection)
        @param reason: str use to advertise reason of lost connection
        """
        if reason.type == RDPSecurityNegoFail and self._security != "rdp":
            log.info("due to RDPSecurityNegoFail try standard security layer")
            self._security = rdp.SecurityLevel.RDP_LEVEL_RDP
            connector.connect()
            return
        
        log.info("connection lost : %s"%reason)
        RDPScreenShotFactory.__STATE__.append((connector.host, connector.port, reason))
        RDPScreenShotFactory.__INSTANCE__ -= 1
        if(RDPScreenShotFactory.__INSTANCE__ == 0):
            self._reactor.stop()
            self._app.exit()
        
    def clientConnectionFailed(self, connector, reason):
        """
        @summary: Connection failed event
        @param connector: twisted connector use for rdp connection (use reconnect to restart connection)
        @param reason: str use to advertise reason of lost connection
        """
        log.info("connection failed : %s"%reason)
        RDPScreenShotFactory.__STATE__.append((connector.host, connector.port, reason))
        RDPScreenShotFactory.__INSTANCE__ -= 1
        if(RDPScreenShotFactory.__INSTANCE__ == 0):
            self._reactor.stop()
            self._app.exit()
        
        
    def buildObserver(self, controller, addr):
        """
        @summary: build ScreenShot observer
        @param controller: RDPClientController
        @param addr: address of target
        """
        class ScreenShotObserver(rdp.RDPClientObserver):
            """
            @summary: observer that connect, cache every image received and save at deconnection
            """
            def __init__(self, controller, width, height, path, timeout, reactor):
                """
                @param controller: {RDPClientController}
                @param width: {integer} width of screen
                @param height: {integer} height of screen
                @param path: {str} path of output screenshot
                @param timeout: {float} close connection after timeout s without any updating
                @param reactor: twisted reactor
                """
                rdp.RDPClientObserver.__init__(self, controller)
                self._buffer = QtGui.QImage(width, height, QtGui.QImage.Format_RGB32)
                self._path = path
                self._timeout = timeout
                self._startTimeout = False
                self._reactor = reactor
                
            def onUpdate(self, destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data):
                """
                @summary: callback use when bitmap is received 
                """
                image = RDPBitmapToQtImage(width, height, bitsPerPixel, isCompress, data);
                with QtGui.QPainter(self._buffer) as qp:
                #draw image
                    qp.drawImage(destLeft, destTop, image, 0, 0, destRight - destLeft + 1, destBottom - destTop + 1)
                if not self._startTimeout:
                    self._startTimeout = False
                    self._reactor.callLater(self._timeout, self.checkUpdate)
                   
            def onReady(self):
                """
                @summary: callback use when RDP stack is connected (just before received bitmap)
                """
                log.info("connected %s"%addr)
            
            def onSessionReady(self):
                """
                @summary: Windows session is ready
                @see: rdp.RDPClientObserver.onSessionReady
                """
                pass
            
            def onClose(self):
                """
                @summary: callback use when RDP stack is closed
                """
                log.info("save screenshot into %s"%self._path)
                self._buffer.save(self._path)
                check_ssdeep_hash(self._path)

            def checkUpdate(self):
                self._controller.close();
                
        controller.setScreen(width, height);
        controller.setSecurityLevel(self._security)
        return ScreenShotObserver(controller, self._width, self._height, self._path, self._timeout, self._reactor)
    
def main(width, height, path, timeout, hosts):
    """
    @summary: main algorithm
    @param height: {integer} height of screenshot
    @param width: {integer} width of screenshot
    @param timeout: {float} in sec
    @param hosts: {list(str(ip[:port]))}
    @return: {list(tuple(ip, port, Failure instance)} list of connection state
    """
    #create application
    app = QtGui.QApplication(sys.argv)
    
    #add qt4 reactor
    import qt4reactor
    qt4reactor.install()
    
    from twisted.internet import reactor
        
    for host in hosts:      
        if ':' in host:
            ip, port = host.split(':')
        else:
            ip, port = host, "3389"
            
        reactor.connectTCP(ip, int(port), RDPScreenShotFactory(reactor, app, width, height, path + "%s.jpg"%ip, timeout))
        
    reactor.runReturn()
    app.exec_()
    return RDPScreenShotFactory.__STATE__
        
def help():
    print "Usage: rdpy-rdpscreenshot [options] ip[:port]"
    print "\t-w: width of screen default value is 1024"
    print "\t-l: height of screen default value is 800"
    print "\t-o: file path of screenshot default(/tmp/rdpy-rdpscreenshot.jpg)"
    print "\t-t: timeout of connection without any updating order (default is 2s)"
        
if __name__ == '__main__':
    #default script argument
    width = 1024
    height = 800
    path = "/tmp/"
    timeout = 5.0
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hw:l:o:t:")
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
        elif opt == "-w":
            width = int(arg)
        elif opt == "-l":
            height = int(arg)
        elif opt == "-o":
            path = arg
        elif opt == "-t":
            timeout = float(arg)
    
    main(width, height, path, timeout, args)
