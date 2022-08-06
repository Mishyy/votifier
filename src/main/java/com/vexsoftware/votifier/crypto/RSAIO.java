/*
 * Copyright (C) 2011 Vex Software LLC
 * This file is part of Votifier.
 *
 * Votifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Votifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Votifier.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.vexsoftware.votifier.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.jetbrains.annotations.NotNull;

/**
 * Static utility methods for saving and loading RSA key pairs.
 *
 * @author Blake Beaupain
 */
public final class RSAIO {

	private static final String PUB_KEY = "public.key";
	private static final String PRIV_KEY = "private.key";

	/**
	 * Saves the key pair to the disk.
	 *
	 * @param directory The directory to save to
	 * @param keyPair   The key pair to save
	 * @throws Exception If an error occurs
	 */
	public static void save(final @NotNull File directory, final @NotNull KeyPair keyPair) throws Exception {
		final PrivateKey privateKey = keyPair.getPrivate();
		final PublicKey publicKey = keyPair.getPublic();

		// Store the public key.
		final X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKey.getEncoded());
		try (final FileOutputStream out = new FileOutputStream(new File(directory, PUB_KEY))) {
			out.write(DatatypeConverter.printBase64Binary(publicSpec.getEncoded()).getBytes());
		}

		// Store the private key.
		final PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		try (final FileOutputStream out = new FileOutputStream(new File(directory, PRIV_KEY))) {
			out.write(DatatypeConverter.printBase64Binary(privateSpec.getEncoded()).getBytes());
		}
	}

	/**
	 * Loads an RSA key pair from a directory. The directory must have the files
	 * "public.key" and "private.key".
	 *
	 * @param directory The directory to load from
	 * @return The key pair
	 * @throws Exception If an error occurs
	 */
	public static KeyPair load(File directory) throws Exception {

		// Read the public key file.
		byte[] encodedPubKey;
		final File pubKey = new File(directory, PUB_KEY);
		try (final FileInputStream in = new FileInputStream(pubKey)) {
			encodedPubKey = new byte[(int) pubKey.length()];
			in.read(encodedPubKey);
			encodedPubKey = DatatypeConverter.parseBase64Binary(new String(encodedPubKey));
		}

		// Read the private key file.
		byte[] encodedPrivKey;
		final File privKey = new File(directory, PRIV_KEY);
		try (final FileInputStream in = new FileInputStream(privKey)) {
			encodedPrivKey = new byte[(int) privKey.length()];
			in.read(encodedPrivKey);
			encodedPrivKey = DatatypeConverter.parseBase64Binary(new String(encodedPrivKey));
		}

		// Instantiate and return the key pair.
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(encodedPubKey)), keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivKey)));
	}

}