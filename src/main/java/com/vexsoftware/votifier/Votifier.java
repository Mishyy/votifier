/*
 * Copyright (C) 2012 Vex Software LLC
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
package com.vexsoftware.votifier;

import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
import com.vexsoftware.votifier.net.VoteReceiver;
import java.io.File;
import java.security.KeyPair;
import java.util.logging.Level;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * The main Votifier plugin class.
 *
 * @author Blake Beaupain
 * @author Kramer Campbell
 */
public final class Votifier extends JavaPlugin {

	/**
	 * The current Votifier version.
	 */
	private String version;

	/**
	 * The vote receiver.
	 */
	private VoteReceiver voteReceiver;

	/**
	 * The RSA key pair.
	 */
	private KeyPair keyPair;

	/**
	 * Debug mode flag
	 */
	private boolean debug;

	@Override
	public void onDisable() {
		// Interrupt the vote receiver.
		if (voteReceiver != null) {
			voteReceiver.shutdown();
		}
		getLogger().info("Votifier disabled.");
	}

	@Override
	public void onLoad() {
		getConfig().options().copyDefaults(true);
		saveDefaultConfig();
	}

	@Override
	public void onEnable() {
		// Set the plugin version.
		version = getDescription().getVersion();

		/*
		 * Use IP address from server.properties as a default for
		 * configurations. Do not use InetAddress.getLocalHost() as it most
		 * likely will return the main server address instead of the address
		 * assigned to the server.
		 */
		String hostAddr = getServer().getIp();
		if (hostAddr == null || hostAddr.length() == 0) {
			hostAddr = "0.0.0.0";
		}

		/*
		 * Create RSA directory and keys if it does not exist; otherwise, read
		 * keys.
		 */
		final File rsaDir = new File(getDataFolder(), "rsa");
		if (!rsaDir.exists()) {
			if (rsaDir.mkdir()) {
				throw new RuntimeException("Unable to create the RSA key folder " + rsaDir);
			}

			try {
				keyPair = RSAKeygen.generate(this, 2048);
				RSAIO.save(rsaDir, keyPair);
			} catch (Exception e) {
				getLogger().log(Level.SEVERE, "Error reading configuration file or RSA keys", e);
				getLogger().severe("Votifier did not initialize properly!");
			}
		} else {
			try {
				keyPair = RSAIO.load(rsaDir);
			} catch (Exception e) {
				getLogger().log(Level.SEVERE, "Error reading configuration file or RSA keys", e);
				getLogger().severe("Votifier did not initialize properly!");
			}
		}

		// Initialize the receiver.
		debug = getConfig().getBoolean("debug");
		if (debug) {
			getLogger().info("DEBUG mode enabled!");
		}

		try {
			voteReceiver = new VoteReceiver(this, getConfig().getString("host", hostAddr), getConfig().getInt("port"));
			voteReceiver.start();
			getLogger().info("Votifier enabled.");
		} catch (Exception e) {
			getLogger().severe("Votifier did not initialize properly!");
		}
	}

	/**
	 * Gets the version.
	 *
	 * @return The version
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Gets the vote receiver.
	 *
	 * @return The vote receiver
	 */
	public VoteReceiver getVoteReceiver() {
		return voteReceiver;
	}

	/**
	 * Gets the keyPair.
	 *
	 * @return The keyPair
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

	public boolean isDebug() {
		return debug;
	}

}