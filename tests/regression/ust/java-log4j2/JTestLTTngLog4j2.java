/*
 * SPDX-FileCopyrightText: 2015 Michael Jeanson <mjeanson@efficios.com>
 * SPDX-FileCopyrightText: 2014 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2014 Christian Babeux <christian.babeux@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

import java.io.IOException;
import java.lang.Integer;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class JTestLTTngLog4j2 {

	/**
	 * Application start
	 *
	 * @param args
	 *            Command-line arguments
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String args[]) throws IOException, InterruptedException {

		Logger console = LogManager.getLogger("console-event-1");
		Logger lttng = LogManager.getLogger("log4j2-event-1");
		Logger lttng2 = LogManager.getLogger("log4j2-event-2");

		int nrIter = Integer.parseInt(args[0]);
		int waitTime = Integer.parseInt(args[1]); /* milliseconds */
		int fire_debug_tp = 0;
		int fire_second_tp = 0;

		if (args.length > 2) {
			fire_debug_tp = Integer.parseInt(args[2]);
		}
		if (args.length > 3) {
			fire_second_tp = Integer.parseInt(args[3]);
		}

		console.info("CONSOLE only event.");

		for (int iter = 0; iter < nrIter; iter++) {
			lttng.info("LOG4J2 INFO tp fired!");
			if (fire_debug_tp == 1) {
				/* Third arg, trigger debug TP. */
				lttng.debug("LOG4J2 DEBUG tp fired");
			}
			Thread.sleep(waitTime);
		}

		if (fire_second_tp == 1) {
			lttng2.info("LOG4J2 INFO second logger fired");
		}
	}
}
