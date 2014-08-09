from electrum.util import print_error

import httplib, urllib
import socket
import hashlib
import json
from urlparse import urlparse, parse_qs
try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from gui.qt.util import ok_cancel_buttons
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui
from electrum.plugins import BasePlugin
from electrum.i18n import _

from electrum_gui.qt import HelpButton, EnterButton

from electrum import cryptocorp

from electrum_gui.qt.qrcodewidget import QRCodeWidget

from random import SystemRandom
from base64 import b32encode
from electrum.version import ELECTRUM_VERSION

class Plugin(BasePlugin):
    def __init__(self, gui, name):
        self.wallet = None
        BasePlugin.__init__(self, gui, name)

    def fullname(self):
        return _('CryptoCorp Digital Oracle')

    def description(self):
        return _("This plugin allows the creation of a multi-signature account with one key implementing specific business rules.")

    def version(self):
        return "0.0.1"

    def init(self):
        self.window = self.gui.main_window
        self.window.deferral_question = self.deferral_question
        cryptocorp.set_recovery_mode(self.recovery())
        from electrum.plugins import plugins
        self.scanner = None
        for plugin in plugins:
            if plugin.name == 'qrscanner':
                self.scanner = plugin

    def deferral_question(self, de):
        d = QDialog()
        layout = QGridLayout(d)
        label = QLabel(str(de))
        label.setWordWrap(True)
        layout.addWidget(label,0,0,1,2)

        otp = None
        code = None

        if 'otp' in de.verifications:
            layout.addWidget(QLabel("One time password: "),1,0)

            otp = QLineEdit()

            layout.addWidget(otp, 1,1)

        if 'code' in de.verifications:
            layout.addWidget(QLabel("Code sent to you by SMS: "),1,0)

            code = QLineEdit()

            layout.addWidget(code, 1,1)

        resubmit = QPushButton(_("Resubmit"))
        resubmit.clicked.connect(d.accept)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        layout.addWidget(resubmit,2,2)
        layout.addWidget(c,2,1)

        if d.exec_():
            if otp:
                de.otp = str(otp.text())
            if code:
                de.code = str(code.text())
            return True
        else:
            return False

    def load_wallet(self, wallet):
        self.init()
        if not self.wallet:
            self.window.new_hdm_account = self.window.wallet_menu.addAction(_("&New HDM account"), self.new_account_dialog)
        self.wallet = wallet

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def base_url(self):
        return self.config.get("base_url", "https://s.digitaloracle.co/")

    def recovery(self):
        return self.config.get("recovery", False)

    def requires_settings(self):
        return True

    def account_detail(self, k, vbox):
        print "detail for %s" %(k)
        account = self.wallet.accounts[k]
        account_dump = account.dump()
        xpub = cryptocorp.SerializeExtendedPublicKey(2, "00000000".decode('hex'), 0, account_dump['c'].decode('hex'), account_dump['cK'].decode('hex'))
        vbox.addWidget(QLabel(_("Extended Public Key:")))
        xpub_line = QLabel(xpub)
        xpub_line.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(xpub_line)
        qrw = QRCodeWidget(xpub)
        vbox.addWidget(qrw)

    def settings_dialog(self):
        def check_url(url):
            pass

        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_("Oracle base URL: ")),0,0)

        self.url_edit = QLineEdit(self.base_url())
        self.url_edit.textChanged.connect(check_url)

        layout.addWidget(self.url_edit, 0,1,1,2)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(d.accept)

        self.recovery_box = QCheckBox(_(""))
        self.recovery_box.setCheckState(Qt.Checked if self.recovery() else Qt.Unchecked)

        layout.addWidget(self.recovery_box,2,1)
        label = QLabel(_("Recovery: in this mode transactions are to be signed by the recovery key. The Oracle will not be contacted"))
        label.setWordWrap(True)
        layout.addWidget(label, 2, 0)
        layout.addWidget(c,4,1)
        layout.addWidget(self.accept,4,2)

        check_url(self.base_url())

        if d.exec_():
          self.config.set_key("base_url", str(self.url_edit.text()))
          self.config.set_key("recovery", self.recovery_box.checkState() == Qt.Checked)

          cryptocorp.set_recovery_mode(self.recovery())
          return True
        else:
          return False

    def enable(self):
        self.load_wallet(self.gui.main_window.wallet)
        self.set_enabled(True)
        return True

    def new_account_dialog(self):
        dialog = QDialog(self.window)
        dialog.setModal(1)
        dialog.setWindowTitle(_("New Account"))

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Account name')+':'))
        e = QLineEdit()
        vbox.addWidget(e)

        msg = _("Please fill in the fields below for Oracle accounts:")
        l = QLabel(msg)
        l.setWordWrap(True)
        vbox.addWidget(l)

        vbox.addWidget(QLabel(_('Email (optional)')+':'))
        email = QLineEdit()
        vbox.addWidget(email)

        vbox.addWidget(QLabel(_('Phone (optional)')+':'))
        phone = QLineEdit()
        vbox.addWidget(phone)

        vbox.addWidget(QLabel(_('Velocity limit')+':'))
        velocity_1 = QLineEdit("0.002")
        vbox.addWidget(velocity_1)

        vbox.addWidget(QLabel(_('Delay')+':'))
        delay_2 = QLineEdit("60")
        vbox.addWidget(delay_2)

        hbox = QHBoxLayout()
        vbox1 = QVBoxLayout()
        hbox.addLayout(vbox)
        hbox.addLayout(vbox1)

        vbox1.addWidget(QLabel(_('Backup Key (xpub)')+':'))
        #backup = QLineEdit()
        backup = QLineEdit('xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')
        vbox1.addWidget(backup)

        def fill_from_qr(button):
            res = self.scanner.scan_qr()
            if res is None:
                return
            if not res.startswith("xpub"):
                QMessageBox.warning(self.gui.main_window, _('Error'), _('Not an extended public key'), _('OK'))
            backup.setText(res)

        if self.scanner and self.scanner.is_enabled():
            b = QPushButton(_("Scan QR code"))
            b.clicked.connect(fill_from_qr)
            vbox1.addWidget(b)

        vbox1.addWidget(QLabel(_('OTP (optional)')+':'))

        otp = QLineEdit()
        vbox1.addWidget(otp)

        qrw = QRCodeWidget()
        vbox1.addWidget(qrw)

        otp_secret = b32encode(("%x"%(SystemRandom().getrandbits(120))).decode('hex'))
        print otp_secret

        def check_name():
            if (str(e.text()) != ""):
                qrw.set_addr("otpauth://totp/Digital-Oracle-%s?secret=%s"%(e.text(), otp_secret))
            else:
                qrw.set_addr("")
            qrw.update_qr()

        e.textChanged.connect(check_name)
        check_name()

        vbox.addLayout(ok_cancel_buttons(dialog))
        dialog.setLayout(hbox)
        r = dialog.exec_()
        if not r: return

        name = str(e.text())
        if not name: return

        email_text = str(email.text())
        phone_text = str(phone.text())
        velocity_1_text = str(velocity_1.text())
        delay_2_text = str(delay_2.text())
        backup_text = str(backup.text())
        otp_text = str(otp.text())
        parameters = {
                'levels': [
                    {
                        'value': float(velocity_1_text),
                        'asset': 'BTC',
                        'period': 60,
                    },
                    {
                        'delay': (int(delay_2_text) if delay_2_text != "" else None)
                        },
                    ],
                    }
        if phone_text and phone_text != "":
            parameters['levels'][1]['calls'] = ['phone', 'email']
            # TODO

        if otp_text and otp_text != "":
            parameters['authenticator'] = {
                    'firstValue': otp_text,
                    'secret': otp_secret,
                    'type': 'totp'
                    }
            parameters['levels'][1]['verifications'] = ['otp']

        pii = {
                "phone": phone_text,
                "email": email_text
                }

        if backup_text:
            i = self.wallet.next_oracle_account()
            my_key = self.wallet.oracle_account(i)[0]
            oracle_url = cryptocorp.make_keychain(self.base_url(), my_key, backup_text, parameters, pii)
            self.wallet.create_oracle_account(oracle_url, backup_text, i, name)
        else:
            self.wallet.create_pending_account('1', name)

        self.window.update_receive_tab()
        self.window.tabs.setCurrentIndex(2)


def debug_trace():
  '''Set a tracepoint in the Python debugger that works with Qt'''
  from PyQt4.QtCore import pyqtRemoveInputHook
  from pdb import set_trace
  pyqtRemoveInputHook()
  set_trace()
