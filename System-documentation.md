# BeHappy Developer Documentation: v:1.0.1

## Loggers

1. **INFO level**: log at this level all actions that are user-driven, or system specific (ie regularly scheduled operations…). This will certainly be the level at which the program will run when in production. Log at this level all the notable events that are not considered an error.
2. **WARNING level**: log at this level all events that could potentially become an error. For instance if one database call took more than a predefined time, or if an in-memory cache is near capacity. This will allow proper automated alerting, and during troubleshooting will allow to better understand how the system was behaving before the failure.
3. **ERROR level**: log every error condition at this level. That can be API calls that return errors or internal error conditions.
4. **CRITICAL level**: too bad, it’s doomsday. Use this very scarcely, this shouldn’t happen a lot in a real program. Usually logging at this level signifies the end of the program. For instance, if a network daemon can’t bind a network socket, log at this level and exit is the only sensible thing to do.

`yo`
