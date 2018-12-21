package com.microsoft.sqlserver.jdbc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Random;

import com.microsoft.sqlserver.jdbc.jtds.NtlmAuth;

final class NtlmAuthentication extends SSPIAuthentication {
	private final SQLServerConnection con;

	public NtlmAuthentication(SQLServerConnection con) {
		this.con = con;
	}

	private byte[] sendNtlmInitial() {
		String domain = con.activeConnectionProperties.getProperty(SQLServerDriverStringProperty.DOMAIN.toString())
				.toUpperCase(Locale.ENGLISH);
		int NTLM = Integer
				.parseInt(con.activeConnectionProperties.getProperty(SQLServerDriverIntProperty.NTLM.toString()));
		// TODO: Does the domain matter? It seems like anything is passible as the
		// domain for ntlmInitial...
		// final int domainByteLen = domain.length()*2;
		final byte[] domainUtf8 = domain.getBytes(StandardCharsets.UTF_8);
		final int domainUtf8Len = domainUtf8.length;
		final int fullLen = 32 + domainUtf8Len;

		final ByteBuffer buf = ByteBuffer.allocate(fullLen).order(ByteOrder.LITTLE_ENDIAN);
		// host and domain name are _narrow_ strings.
		// byte[] hostBytes = localhostname.getBytes("UTF8");

		final byte[] header = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
		buf.put(header); // header is ascii "NTLMSSP\0"
		buf.putInt(1); // sequence number = 1
		if (NTLM == 2)
			buf.putInt(0x8b205); // flags (same as below, only with Request Target and NTLM2 set)
		else
			buf.putInt(0xb201); // flags (see below)

		// NOTE: flag reference:
		// 0x80000 = negotiate NTLM2 key
		// 0x08000 = negotiate always sign
		// 0x02000 = client is sending workstation name
		// 0x01000 = client is sending domain name
		// 0x00200 = negotiate NTLM
		// 0x00004 - Request Target, which requests that server send target
		// 0x00001 = negotiate Unicode

		// domain info
		buf.putShort((short) domainUtf8Len);
		buf.putShort((short) domainUtf8Len);
		buf.putInt(32); // offset, relative to start of auth block.

		// host info
		// NOTE(mdb): not sending host info; hope this is ok!
		buf.putShort((short) domainUtf8Len);
		buf.putShort((short) domainUtf8Len);
		buf.putInt(32); // offset, relative to start of auth block.

		// add the variable length data at the end...
		buf.put(domainUtf8);
		// writeString(buf, domain);
		return buf.array();
	}

	private static final void putStrLilEndian(ByteBuffer buf, String str) {
		int len = str.length();
		for (int i = 0; i < len; i++) {
			int c = str.charAt(i);
			buf.put((byte) ((c >> 0) & 0xFF));
			buf.put((byte) ((c >> 8) & 0xFF));
		}
	}

	private byte[] sendNtlmChallengeResponse(byte[] nonce, byte[] ntlmTarget) {
		String user = con.activeConnectionProperties.getProperty(SQLServerDriverStringProperty.USER.toString());
		String pwd = con.activeConnectionProperties.getProperty(SQLServerDriverStringProperty.PASSWORD.toString());
		String domain = con.activeConnectionProperties.getProperty(SQLServerDriverStringProperty.DOMAIN.toString())
				.toUpperCase(Locale.ENGLISH);
		int NTLM = Integer
				.parseInt(con.activeConnectionProperties.getProperty(SQLServerDriverIntProperty.NTLM.toString()));
		// Prepare and Set NTLM Type 2 message appropriately
		// Author: mahi@aztec.soft.net

		// host and domain name are _narrow_ strings.
		// byte[] domainBytes = domain.getBytes("UTF8");
		// byte[] user = user.getBytes("UTF8");

		final byte[] lmAnswer, ntAnswer;
		// the response to the challenge...

		if (NTLM == 2) {
			// TODO: does this need to be random?
			// byte[] clientNonce = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			// 0x08 };
			byte[] clientNonce = new byte[8];
			(new Random()).nextBytes(clientNonce);

			lmAnswer = NtlmAuth.answerLmv2Challenge(domain, user, pwd, nonce, clientNonce);
			ntAnswer = NtlmAuth.answerNtlmv2Challenge(domain, user, pwd, nonce, ntlmTarget, clientNonce);
		} else {
			// LM/NTLM (v1)
			lmAnswer = NtlmAuth.answerLmChallenge(pwd, nonce);
			ntAnswer = NtlmAuth.answerNtChallenge(pwd, nonce);
		}

		final int domainArrLen = domain.length() * 2;
		final int userArrLen = user.length() * 2;
		final int size = 64 + domainArrLen + userArrLen + lmAnswer.length + ntAnswer.length;
		final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
		final byte[] header = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
		buf.put(header); // header is ascii "NTLMSSP\0"
		buf.putInt(3); // sequence number = 3
		// mdb: not sending hostname; I hope this is ok!
		final int hostLenInBytes = 0; // localhostname.length()*2;
		int pos = 64 + domainArrLen + userArrLen + hostLenInBytes;
		// lan man response: length and offset
		buf.putShort((short) lmAnswer.length);
		buf.putShort((short) lmAnswer.length);
		buf.putInt(pos);
		pos += lmAnswer.length;
		// nt response: length and offset
		buf.putShort((short) ntAnswer.length);
		buf.putShort((short) ntAnswer.length);
		buf.putInt(pos);
		pos = 64;
		// domain
		buf.putShort((short) domainArrLen);
		buf.putShort((short) domainArrLen);
		buf.putInt(pos);
		pos += domainArrLen;

		// user
		buf.putShort((short) userArrLen);
		buf.putShort((short) userArrLen);
		buf.putInt(pos);
		pos += userArrLen;
		// local hostname
		buf.putShort((short) hostLenInBytes);
		buf.putShort((short) hostLenInBytes);
		buf.putInt(pos);
		pos += hostLenInBytes;
		// unknown
		buf.putShort((short) 0);
		buf.putShort((short) 0);
		buf.putInt(pos);
		// flags
		if (NTLM == 2)
			buf.putInt(0x88201);
		else
			buf.putInt(0x8201);
		// variable length stuff...
		putStrLilEndian(buf, domain);
		putStrLilEndian(buf, user);

		// Not sending hostname...I hope this is OK!
		// comm.appendChars(localhostname);

		// the response to the challenge...
		buf.put(lmAnswer);
		buf.put(ntAnswer);
		return buf.array();
	}

	@Override
	byte[] GenerateClientContext(byte[] pin, boolean[] done) throws SQLServerException {
		if (pin == null || pin.length == 0) {
			return sendNtlmInitial();
		}

		final int headerOffset = 40; // The assumes the context is always there, which appears to be the case.

		if (pin.length < headerOffset)
			throw new RuntimeException("NTLM challenge: packet is too small: " + pin.length);

		final int seq = Util.readInt(pin, 8);
		if (seq != 2)
			throw new RuntimeException("NTLM challenge: got unexpected sequence number: " + seq);

		/* final int flags = */ Util.readInt(pin, 20);
		// NOTE: the context is always included; if not local, then it is just
		// set to all zeros.
		// boolean hasContext = ((flags & 0x4000) != 0);
		// final boolean hasContext = true;
		// NOTE: even if target is omitted, the length will be zero.
		// final boolean hasTarget = ((flags & 0x800000) != 0);

		// extract the target, if present. This will be used for ntlmv2 auth.
		// header has: 2 byte lenght, 2 byte allocated space, and four-byte offset.
		int size = Util.readShort(pin, headerOffset);
		int offset = Util.readInt(pin, headerOffset + 4);
		byte[] ntlmTarget = new byte[size];
		System.arraycopy(pin, offset, ntlmTarget, 0, size);

		byte[] nonce = new byte[8];
		System.arraycopy(pin, 24, nonce, 0, 8);

		return sendNtlmChallengeResponse(nonce, ntlmTarget);
	}

	@Override
	int ReleaseClientContext() throws SQLServerException {
		// Perform nothing.
		return 0;
	}
}
