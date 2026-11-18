# SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

require "openssl"

# MLS-TLS 335f9db and two-party profile e2cb1ac.
# RFC 8446 sections 5.2, 5.3, and 7.3. MLS suite 0x0907 uses SHA384/AES-256-GCM.
puts "# SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>"
puts "# SPDX-License-Identifier: AGPL-3.0-or-later"
puts "# MLS-TLS 335f9db, two-party profile e2cb1ac, and RFC 8446."
puts "# hash cipher key iv nonce(seq=0x0102030405060708) record(seq=0) record(seq=1)"

def expand(hash, secret, label, size)
  label = "tls13 " + label
  info = [size, label.bytesize].pack("nC") + label + "\x00"
  OpenSSL::HMAC.digest(hash, secret, info + "\x01").byteslice(0, size)
end

def nonce(iv, sequence)
  mask = [0, sequence].pack("NQ>")
  iv.bytes.zip(mask.bytes).map { |byte, value| byte ^ value }.pack("C*")
end

def record(name, key, iv, sequence)
  payload = [0, 255, 77, 76, 83, 0, 23, 0, 0, 0].pack("C*")
  header = [23, 0x0303, payload.bytesize + 16].pack("Cnn")
  cipher = OpenSSL::Cipher.new(name)
  cipher.encrypt
  cipher.key = key
  cipher.iv = nonce(iv, sequence)
  cipher.auth_data = header
  header + cipher.update(payload) + cipher.final + cipher.auth_tag
end

{ "SHA256" => 32, "SHA384" => 48, "SHA512" => 64 }.each do |hash, length|
  secret = (0...length).to_a.pack("C*")
  { "aes-128-gcm" => 16, "aes-256-gcm" => 32, "chacha20-poly1305" => 32 }.each do |name, size|
    key = expand(hash, secret, "key", size)
    iv = expand(hash, secret, "iv", 12)
    values = [key, iv, nonce(iv, 0x0102030405060708), record(name, key, iv, 0), record(name, key, iv, 1)]
    puts ([hash, name] + values.map { |bytes| bytes.unpack1("H*") }).join(" ")
  end
end
