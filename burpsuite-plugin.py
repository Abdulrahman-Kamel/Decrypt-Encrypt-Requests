import threading
import urlparse
from burp import IBurpExtender
from burp import IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem
from base64 import b64encode
import base64
from javax.crypto import Cipher, SecretKey, SecretKeyFactory
from javax.crypto.spec import IvParameterSpec, SecretKeySpec

key = "*********0052021"
iv = "*********052021"

# AES CBC encryption function
def aes_cbc_encrypt(plaintext, key, iv):
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    secret_key = SecretKeySpec(key_bytes, "AES")
    iv_param_spec = IvParameterSpec(iv_bytes)
    cipher.init(Cipher.ENCRYPT_MODE, secret_key, iv_param_spec)
    encrypted_bytes = cipher.doFinal(plaintext.encode('utf-8'))
    encrypted_text = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_text

# AES CBC decryption function
def aes_cbc_decrypt(ciphertext, key, iv):
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    secret_key = SecretKeySpec(key_bytes, "AES")
    iv_param_spec = IvParameterSpec(iv_bytes)
    cipher.init(Cipher.DECRYPT_MODE, secret_key, iv_param_spec)
    decrypted_bytes = cipher.doFinal(base64.b64decode(ciphertext))
    decrypted_text = decrypted_bytes.tostring().decode('utf-8')
    return decrypted_text

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Decrypt Reqeust")
        callbacks.registerContextMenuFactory(self)

    # Add the missing 'projectConfig' dictionary with default values
    projectConfig = {
        'scanner': {
            'active_scanning_optimization': {
                'scan_accuracy': 100
            }
        }
    }

    # Access the scan_accuracy value from projectConfig
    scanAccuracy = projectConfig['scanner']['active_scanning_optimization']['scan_accuracy']

    def createMenuItems(self, invocation):
        menu = ArrayList()
        selected_messages = invocation.getSelectedMessages()
        if len(selected_messages) == 1:
            menu.add(JMenuItem("Encrypt", actionPerformed=lambda event: self.encodeBody(selected_messages[0])))
            menu.add(JMenuItem("Decrypt", actionPerformed=lambda event: self.decodeBody(selected_messages[0])))
        return menu

    def encodeBody(self, request_response):
        request = request_response.getRequest()
        response = request_response.getResponse()

        # Get the request information
        request_info = self._helpers.analyzeRequest(request_response)
        body_offset = request_info.getBodyOffset()
        body_bytes = request[body_offset:]
        body = self._helpers.bytesToString(body_bytes)

        # Perform your desired action with the request body
        encoded_body = self.encodeData(body)
        encoded_body_bytes = self._helpers.stringToBytes(encoded_body)

        # Get the URL of the intercepted request
        url = request_info.getUrl().toString()

        # Check if the URL has query parameters
        if "?" in url:
            url_parts = urlparse.urlsplit(url)
            path = url_parts.path
            query = url_parts.query
            fragment = url_parts.fragment

            # Encode the query parameters using base64
            encoded_query = self.encodeData(query)

            # Build the encoded URL with the updated query parameters
            encoded_url = path + "?" + encoded_query + fragment
        else:
            encoded_url = url

        # Modify the request with the encoded body and updated URL
        modified_request = self._helpers.buildHttpMessage([request_info.getMethod() + " " + encoded_url + " HTTP/1.1"] + request_info.getHeaders()[1:], encoded_body_bytes)
        request_response.setRequest(modified_request)


    def decodeBody(self, request_response):
        request = request_response.getRequest()
        response = request_response.getResponse()

        # Get the request information
        request_info = self._helpers.analyzeRequest(request_response)
        body_offset = request_info.getBodyOffset()
        body_bytes = request[body_offset:]
        body = self._helpers.bytesToString(body_bytes)

        # Perform your desired action with the request body
        decoded_body = self.decodeData(body)
        decoded_body_bytes = self._helpers.stringToBytes(decoded_body)

        # Get the URL of the intercepted request
        url = request_info.getUrl().toString()

        # Check if the URL has query parameters
        if "?" in url:
            url_parts = urlparse.urlsplit(url)
            path = url_parts.path
            query = url_parts.query
            fragment = url_parts.fragment

            # Encode the query parameters using base64
            decoded_query = self.decodeData(query)

            # Build the encoded URL with the updated query parameters
            decoded_url = path + "?" + decoded_query + fragment
        else:
            decoded_url = url

        # Modify the request with the encoded body and updated URL
        modified_request = self._helpers.buildHttpMessage([request_info.getMethod() + " " + decoded_url + " HTTP/1.1"] + request_info.getHeaders()[1:], decoded_body_bytes)
        request_response.setRequest(modified_request)


    def encodeData(self, data):
        encodedData = aes_cbc_encrypt(data, key, iv)
        return encodedData

    def decodeData(self, data):
        decodedData = aes_cbc_decrypt(data, key, iv)
        return decodedData

# Instantiate the plugin
plugin = BurpExtender()
