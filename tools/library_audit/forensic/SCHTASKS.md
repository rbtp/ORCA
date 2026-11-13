# FORENSIC_SCHTASKS — Forensic.System.ScheduledTasks

- Captures: scheduled tasks from the task XML files under C:/Windows/System32/Tasks (task name, command, arguments, author, run-as user, run level, triggers, registration/start times). The same data is mirrored in the TaskCache registry (SOFTWARE hive).
- Mode: file/registry (runs under the dead-disk remap, reading C:).
- Built-in used: Windows.System.TaskScheduler (wrapped).
- Rows on P: 251.
