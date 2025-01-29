/*
 * SPDX-FileCopyrightText: 2015 Michael Jeanson <mjeanson@efficios.com>
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

import java.io.IOException;
import java.lang.Integer;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.lttng.ust.agent.jul.LttngLogHandler;

public class JTestLTTng {

	/**
	 * Application start
	 *
	 * @param args
	 *            Command-line arguments
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String args[]) throws IOException, InterruptedException {

		Logger lttng = Logger.getLogger("JTestLTTng");
		Logger lttng2 = Logger.getLogger("JTestLTTng2");

		int nrIter = Integer.parseInt(args[0]);
		int waitTime = Integer.parseInt(args[1]);
		int fire_finest_tp = 0;
		int fire_second_tp = 0;

		if (args.length > 2) {
			fire_finest_tp = Integer.parseInt(args[2]);
		}
		if (args.length > 3) {
			fire_second_tp = Integer.parseInt(args[3]);
		}

		/* Instantiate a LTTngLogHandler object, and attach it to our loggers */
		Handler lttngHandler = new LttngLogHandler();
		lttng.addHandler(lttngHandler);
		lttng2.addHandler(lttngHandler);

		lttng.setLevel(Level.FINEST);

		for (int iter = 0; iter < nrIter; iter++) {
			lttng.info("JUL tp fired!");
			if (fire_finest_tp == 1) {
				/* Third arg, trigger finest TP. */
				lttng.finest("JUL FINEST tp fired");
			}
			Thread.sleep(waitTime);
		}

		if (fire_second_tp == 1) {
			lttng2.info("JUL second logger fired");
		}

		/*
		 * Do not forget to close() all handlers so that the agent can shutdown
		 * and the session daemon socket gets cleaned up explicitly.
		 */
		lttngHandler.close();
	}
}
