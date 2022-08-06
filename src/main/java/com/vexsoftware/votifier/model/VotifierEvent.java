package com.vexsoftware.votifier.model;

import org.bukkit.event.Event;
import org.bukkit.event.HandlerList;
import org.jetbrains.annotations.NotNull;

/**
 * {@link VotifierEvent} is a custom Bukkit event class that is sent
 * synchronously to CraftBukkit's main thread allowing other plugins to listener
 * for votes.
 *
 * @author frelling
 */
public final class VotifierEvent extends Event {

	/**
	 * Event listener handler list.
	 */
	private static final HandlerList handlers = new HandlerList();

	/**
	 * Encapsulated vote record.
	 */
	private final Vote vote;

	/**
	 * Constructs a vote event that encapsulated the given vote record.
	 *
	 * @param vote vote record
	 */
	public VotifierEvent(final @NotNull Vote vote) {
		this.vote = vote;
	}

	/**
	 * Return the encapsulated vote record.
	 *
	 * @return vote record
	 */
	public @NotNull Vote getVote() {
		return vote;
	}

	@Override
	public HandlerList getHandlers() {
		return handlers;
	}

}