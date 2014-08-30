import httplib2 as http
import json
import logging
import threading
from socketIO_client import SocketIO

logging.basicConfig(level=logging.DEBUG)

try:
        from urlparse import urlparse
except ImportError:
        from urllib.parse import urlparse

import struct
import bitcoin
import ecdsa
import account
import dateutil.tz
import dateutil.parser
import datetime
from ecdsa.curves import SECP256k1
from wallet import Wallet
from transaction import Transaction
from util import DeferralException
import uuid
from version import ELECTRUM_VERSION

recovery_mode = False

def set_recovery_mode(recovery):
    global recovery_mode
    print "setting recovery = %s"%(recovery)
    recovery_mode = recovery

headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json; charset=UTF-8'
        }

PRIVATE_TEST_VERSION = [
    ( True, False, "0488ADE4"),
    (False, False, "0488B21E"),
    ( True,  True, "04358394"),
    (False,  True, "043587CF"),
]

# generate lookup and reverse lookup
PRIVATE_TEST__VERSION_LOOKUP = dict(((p, t), v.decode("hex")) for p, t, v in PRIVATE_TEST_VERSION)
VERSION__PRIVATE_TEST_LOOKUP = dict((v.decode("hex"), (p, t)) for p, t, v in PRIVATE_TEST_VERSION)


def SerializeExtendedPublicKey(depth, parent_fingerprint, child_number, chain_code, cK):
    """Yield a base58 encoded 78-byte binary blob corresponding to this node."""

    vch = PRIVATE_TEST__VERSION_LOOKUP[(False, False)]
    vch += chr(depth)
    vch += parent_fingerprint
    vch += struct.pack(">L", child_number)
    vch += chain_code
    #    ba += b'\0' + self.secret_exponent_bytes
    vch += cK
    return bitcoin.EncodeBase58Check(vch)

def DeserializeExtendedKey(s):
    """Decode 78-byte binary blob corresponding to this node."""

    data = bitcoin.DecodeBase58Check(s)
    (is_private, is_test) = VERSION__PRIVATE_TEST_LOOKUP[data[0:4]]
    parent_fingerprint = data[5:9]
    child_number, = struct.unpack(">L", data[9:13])
    d = dict(is_private=is_private, is_test=is_test, chain_code=data[13:45], depth=ord(data[4]), parent_fingerprint=parent_fingerprint, child_number=child_number)
    if is_private:
        if ord(data[45]) != 0:
            raise Exception("incorrect private key encoding")
        d['secret'] = data[46:]
    else:
        Q = bitcoin.ser_to_point(data[45:])
        pubkey = ecdsa.VerifyingKey.from_public_point(Q, curve = SECP256k1)
        d['K'] = pubkey.to_string()
        d['cK'] = bitcoin.GetPubKey(pubkey.pubkey, True)
    return d

def propose_key(base_url, my_key, key, role):
    oracle_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:digitaloracle.co:%s"%(my_key)))
    propose_url = base_url + "keychains/" + oracle_id + "/keys"
    h = http.Http()
    body = json.dumps({
        'walletAgent': "HDM-%s"%(ELECTRUM_VERSION),
        'key': key,
        'attributes' : { 'role' : role}
        })
    print "propose to %s %s"%(propose_url, body)
    res, content = h.request(propose_url, 'POST', body, headers)
    if res.status != 200:
        print content
        raise Exception("Error %d from Oracle"%(res.status))

socketIO = None
listen_thread = None
keys_callback = None

def listen_worker(base_url, oracle_id):
    global socketIO
    socketIO = SocketIO(base_url)
    socketIO.on('keys', callback=on_keys)
    socketIO.emit('subscribe', {'c': oracle_id})
    socketIO.wait()

def on_keys(*args):
    keys_callback(args[0])

def start_rendezvous(base_url, my_key, keys_cb):
    global keys_callback
    keys_callback = keys_cb
    base_url = base_url.rstrip('/')
    oracle_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:digitaloracle.co:%s"%(my_key)))
    listen_thread = threading.Thread(target=listen_worker, args=(base_url,oracle_id))
    listen_thread.setDaemon(True)
    listen_thread.start()

def stop_rendezvous():
    global socketIO
    if socketIO:
        socketIO.disconnect()
    socketIO = None

def make_keychain(base_url, my_key, backup_key, parameters, pii):
    oracle_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:digitaloracle.co:%s"%(my_key)))
    #TODO proper URL concat
    oracle_url = base_url + "keychains/" + oracle_id
    print oracle_url
    h = http.Http()
    res, content = h.request(oracle_url, 'GET', None, headers)
    if res.status == 200:
        return oracle_url
    if res.status != 404:
        print content
        raise Exception("Error %d from Oracle"%(res.status))
    body = json.dumps({
        'walletAgent': "HDM-%s"%(ELECTRUM_VERSION),
        'rulesetId': 'default',
        'parameters': parameters,
        'pii': pii,
        'keys': [my_key, backup_key],
        })
    print body
    res, content = h.request(oracle_url, 'POST', body, headers)
    if res.status != 200:
        print content
        raise Exception("Error %d from Oracle"%(res.status))
    print content
    return oracle_url

class OracleDeferralException(DeferralException):
    def __init__(self, message, account, params, verifications):
        Exception.__init__(self, message)
        self.account = account
        self.params = params
        self.verifications = verifications or []
        self.otp = None
        self.code = None

    def retry(self):
        self.account.otp = self.otp
        self.account.code = self.code
        return self.account.sign(*self.params)

class Oracle_Account(account.BIP32_Account_2of3):
    def __init__(self, v):
        self.oracle = v['oracle']
        self.my_key = v['my_key']
        self.backup_key = v['backup_key']
        self.otp = None
        self.code = None

        if not v.has_key('c2'):
            h = http.Http()
            res, content = h.request(self.oracle, 'GET', None, headers)
            if res.status != 200:
                raise Exception("Error %d from Oracle"%(res.status))
            response = json.loads(content)
            if response['result'] != 'success':
                raise Exception("Result %s from Oracle"%(response['result']))
            oracle = DeserializeExtendedKey(response['keys']['default'][0])
            backup = DeserializeExtendedKey(v['backup_key'])
            v['c2'] = backup['chain_code'].encode('hex')
            v['K2'] = backup['K'].encode('hex')
            v['cK2'] = backup['cK'].encode('hex')
            v['c3'] = oracle['chain_code'].encode('hex')
            v['K3'] = oracle['K'].encode('hex')
            v['cK3'] = oracle['cK'].encode('hex')
            print "derived="
            print SerializeExtendedPublicKey(2, "00000000".decode('hex'), 0, v['c'].decode('hex'), v['cK'].decode('hex'))
        account.BIP32_Account_2of3.__init__(self, v)

    def keyID_elements(self, s):
        return [ 'oracle', 'bip32(%s,%s,%s)'%(self.c2.encode('hex'),self.K2.encode('hex'),s) ]

    def redeem_script(self, sequence):
        chain, i = sequence
        pubkey1 = self.get_pubkey(chain, i)
        pubkey2 = self.get_pubkey2(chain, i)
        pubkey3 = self.get_pubkey3(chain, i)
        keys = [pubkey1, pubkey2, pubkey3]
        keys.sort()
        return Transaction.multisig_script(keys, 2)

    def dump(self):
        d = account.BIP32_Account_2of3.dump(self)
        d['oracle'] = self.oracle
        d['backup_key'] = self.backup_key
        d['my_key'] = self.my_key
        return d

    def sign(self, wallet, tx, input_list):
        # If we are in recovery mode, return incomplete tx.  The UI will then
        # prompt the user to export it so that it can be signed by the recovery key.
        if recovery_mode:
            return tx

        # Have the Oracle sign the tx
        input_txs = []
        chain_paths = []
        input_scripts = []
        for i, inp in enumerate(tx.inputs):
            if len(input_list) > i and input_list[i]:
                in_tx = wallet.transactions.get(inp['prevout_hash'])
                input_scripts.append(inp['redeemScript'])
                chain_paths.append("%d/%d"%(input_list[i][0], input_list[i][1]))
                if in_tx:
                    input_txs.append(in_tx.raw)
                else:
                    raise Exception("could not find input transaction %s"%(inp['prevout_hash']))
            else:
                input_scripts.append(None)
                chain_paths.append(None)

        output_chain_paths = []
        for i, (address, value) in enumerate(tx.outputs):
            if not wallet.is_mine(address):
                output_chain_paths.append(None)
            else:
                account, path = wallet.get_address_index(address)
                if wallet.accounts[account] == self:
                    output_chain_paths.append("%d/%d"%(path[0], path[1]))
                else:
                    output_chain_paths.append(None)

        master_keys = [ self.my_key, self.backup_key ]
        req = {
                "walletAgent": "HDM-%s"%(ELECTRUM_VERSION),
                "transaction": {
                    "bytes": tx.raw,
                    "inputScripts": input_scripts,
                    "inputTransactions": input_txs,
                    "chainPaths": chain_paths,
                    "outputChainPaths": output_chain_paths,
                    "masterKeys": master_keys,
                    }
                }
        if self.otp:
            req['verifications'] = {}
            req['verifications']['otp'] = self.otp
        if self.code:
            req['verifications'] = {}
            req['verifications']['code'] = self.code

        self.otp = None
        self.code = None

        print json.dumps(req)

        h = http.Http()
        print "request to %s"%(self.oracle)
        res, content = h.request(self.oracle + "/transactions", 'POST', json.dumps(req), headers)

        print content

        if res.status != 200 and res.status != 400:
            raise Exception("Error %d from Oracle"%(res.status))
        response = json.loads(content)
        if response.has_key('error'):
            raise Exception("Oracle signature failed: %s" %(response['error']))
        if response['result'] == 'deferred':
            if response['deferral'] and response['deferral']['reason'] == 'delay':
                tzlocal = dateutil.tz.tzlocal()
                until = dateutil.parser.parse(response['deferral']['until']).astimezone(tzlocal)
                remain = int((until - datetime.datetime.now(tzlocal)).total_seconds())
                raise OracleDeferralException("Oracle deferred transaction, please resubmit at %s (%s seconds from now)"%(until.strftime("%Y-%m-%d %H:%M:%S"), remain), self, (wallet, tx, input_list), response['deferral'].get('verifications'))
            else:
                raise OracleDeferralException("Oracle deferred transaction, please resubmit after verification", self, (wallet, tx, input_list), response['deferral'].get('verifications'))
        if response['result'] != 'success':
            raise Exception("Result %s from Oracle"%(response['result']))
        tx = Transaction(response['transaction']['bytes'], True)
        return tx

def debug_trace():
  '''Set a tracepoint in the Python debugger that works with Qt'''
  from PyQt4.QtCore import pyqtRemoveInputHook
  from pdb import set_trace
  pyqtRemoveInputHook()
  set_trace()
