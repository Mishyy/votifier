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
package com.vexsoftware.votifier.net;

import com.vexsoftware.votifier.Votifier;
import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.model.VotifierEvent;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import org.jetbrains.annotations.NotNull;

/**
 * The vote receiving server.
 *
 * @author Blake Beaupain
 * @author Kramer Campbell
 */
public final class VoteReceiver extends Thread {

	private final Votifier plugin;

	/**
	 * The host to listen on.
	 */
	private final String host;

	/**
	 * The port to listen on.
	 */
	private final int port;

	/**
	 * The server socket.
	 */
	private final ServerSocket server;

	/**
	 * The running flag.
	 */
	private boolean running = true;

	/**
	 * Instantiates a new vote receiver.
	 *
	 * @param host The host to listen on
	 * @param port The port to listen on
	 */
	public VoteReceiver(final Votifier plugin, String host, int port) {
		this.plugin = plugin;
		this.host = host;
		this.port = port;

		try {
			this.server = new ServerSocket();
			server.bind(new InetSocketAddress(host, port));
		} catch (IOException e) {
			plugin.getLogger().severe("Error initializing vote receiver. Please verify that the configured.");
			plugin.getLogger().severe("IP address and port are not already in use. This is a common problem.");
			plugin.getLogger().log(Level.SEVERE, "with hosting services and, if so, you should check with your hosting provider.", e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Shuts the vote receiver down cleanly.
	 */
	public void shutdown() {
		running = false;
		if (server != null) {
			try {
				server.close();
			} catch (Exception ex) {
				plugin.getLogger().severe("Unable to shut down vote receiver cleanly.");
			}
		}
	}

	@Override
	public void run() {
		// Main loop.
		while (running) {
			try (final Socket socket = server.accept()) {
				socket.setSoTimeout(5000); // Don't hang on slow connections.
				try (final BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {
					// Send them our version.
					writer.write("VOTIFIER " + plugin.getVersion());
					writer.newLine();
					writer.flush();
				}

				try (final InputStream in = socket.getInputStream()) {
					// Read the 256 byte block.
					byte[] block = new byte[256];
					in.read(block, 0, block.length);

					// Decrypt the block.
					block = RSA.decrypt(block, plugin.getKeyPair().getPrivate());
					int position = 0;

					// Perform the opcode check.
					String opcode = readString(block, position);
					position += opcode.length();
					if (!opcode.equals("VOTE")) {
						// Something went wrong in RSA.
						throw new IllegalStateException("Unable to decode RSA.");
					}

					// Create the vote
					final Vote vote = new Vote();
					vote.setServiceName(readString(block, position));
					vote.setUsername(readString(block, position += vote.getServiceName().length()));
					vote.setAddress(readString(block, position += vote.getUsername().length()));
					vote.setTimeStamp(readString(block, position + vote.getAddress().length()));

					if (plugin.isDebug()) {
						plugin.getLogger().info("Received vote record -> " + vote);
					}

					// Call event in a synchronized fashion to ensure that the custom event runs in the the main server thread, not this one.
					plugin.getServer().getScheduler().scheduleSyncDelayedTask(plugin, () -> plugin.getServer().getPluginManager().callEvent(new VotifierEvent(vote)));
				}
			} catch (SocketException e) {
				plugin.getLogger().warning("Protocol error. Ignoring packet - " + e.getLocalizedMessage());
			} catch (BadPaddingException e) {
				plugin.getLogger().warning("Unable to decrypt vote record. Make sure that that your public key");
				plugin.getLogger().log(Level.WARNING, "matches the one you gave the server list.", e);
			} catch (Exception e) {
				plugin.getLogger().log(Level.WARNING, "Exception caught while receiving a vote notification", e);
			}
		}
	}

	/**
	 * Reads a string from a block of data.
	 *
	 * @param data The data to read from
	 * @return The string
	 */
	private @NotNull String readString(byte[] data, int offset) {
		final StringBuilder builder = new StringBuilder();
		for (int i = (offset == 0 ? offset : (offset + 1)); i < data.length; i++) {
			if (data[i] == '\n') {
				break; // Delimiter reached.
			}
			builder.append((char) data[i]);
		}
		return builder.toString();
	}

}