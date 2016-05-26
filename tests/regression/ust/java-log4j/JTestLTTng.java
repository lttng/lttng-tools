/*
 * Copyright (C) 2015 - Michael Jeanson <dgoulet@efficios.com>
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 *                      Christian Babeux <christian.babeux@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

import java.io.IOException;
import java.lang.Integer;

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.log4j.Level;
import org.lttng.ust.agent.log4j.LttngLogAppender;

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

		Logger lttng = Logger.getLogger("log4j-event");
		Logger lttng2 = Logger.getLogger("log4j-event-2");

		/*
		 * Set lowest level to make sure all event levels are logged.
		 * Any jar can override the default log4j rootLogger level
		 * and a logger with no explicit level defaults to the non-null
		 * parent level. Events could be ignored if the inherited value
		 * is too low, thereby failing the test.
		 *
		 * See BSF  -> https://issues.apache.org/jira/browse/BSF-24
		 */
		lttng.setLevel(Level.ALL);
		lttng2.setLevel(Level.ALL);

		int nrIter = Integer.parseInt(args[0]);
		int waitTime = Integer.parseInt(args[1]);
		int fire_debug_tp = 0;
		int fire_second_tp = 0;

		if (args.length > 2) {
			fire_debug_tp = Integer.parseInt(args[2]);
		}
		if (args.length > 3) {
			fire_second_tp = Integer.parseInt(args[3]);
		}

		/* Start with the default Log4j configuration, which logs to console */
		BasicConfigurator.configure();

		/*
		 * Add a LTTng log appender to both loggers, which will also send the
		 * logged events to UST.
		 */
		Appender lttngAppender = new LttngLogAppender();
		lttng.addAppender(lttngAppender);
		lttng2.addAppender(lttngAppender);

		for (int iter = 0; iter < nrIter; iter++) {
			lttng.info("LOG4J tp fired!");
			if (fire_debug_tp == 1) {
				/* Third arg, trigger debug TP. */
				lttng.debug("LOG4J DEBUG tp fired");
			}
			Thread.sleep(waitTime);
		}

		if (fire_second_tp == 1) {
			lttng2.info("LOG4J second logger fired");
		}

		/*
		 * Do not forget to close() all handlers so that the agent can shutdown
		 * and the session daemon socket gets cleaned up explicitly.
		 */
		lttngAppender.close();
	}
}
