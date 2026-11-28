CREATE TABLE `alerts` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`message` text NOT NULL,
	`local_key` text DEFAULT '' NOT NULL,
	`machine_id` text DEFAULT '' NOT NULL,
	`created_by` text NOT NULL,
	`created_by_name` text NOT NULL,
	`created_at` text NOT NULL,
	`resolved_at` text,
	FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `collection_visits` (
	`id` text PRIMARY KEY NOT NULL,
	`local_key` text NOT NULL,
	`local` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`payment_method` text DEFAULT 'cash' NOT NULL,
	`started_at` text NOT NULL,
	`closed_at` text,
	`collector_id` text NOT NULL,
	`collector_name` text NOT NULL,
	`deposits` real DEFAULT 0 NOT NULL,
	`totals_json` text DEFAULT '{}' NOT NULL,
	`cancelled_at` text,
	`cancelled_by` text,
	FOREIGN KEY (`collector_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `field_messages` (
	`id` text PRIMARY KEY NOT NULL,
	`body` text NOT NULL,
	`created_by` text NOT NULL,
	`created_by_name` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `field_notes` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`local_key` text NOT NULL,
	`machine_id` text DEFAULT '' NOT NULL,
	`body` text NOT NULL,
	`created_by` text NOT NULL,
	`created_by_name` text NOT NULL,
	`created_at` text NOT NULL,
	`resolved_at` text,
	FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `machine_collections` (
	`id` text PRIMARY KEY NOT NULL,
	`visit_id` text NOT NULL,
	`machine_id` text NOT NULL,
	`model` text DEFAULT '' NOT NULL,
	`partial_in` real NOT NULL,
	`partial_out` real NOT NULL,
	`global_in` real NOT NULL,
	`global_out` real NOT NULL,
	`manual_counters` integer DEFAULT 0 NOT NULL,
	`drawer` real NOT NULL,
	`taxes` real NOT NULL,
	`net_drawer` real NOT NULL,
	`manager_share` real NOT NULL,
	`exercise_share` real NOT NULL,
	`service_share` real DEFAULT 0 NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`visit_id`) REFERENCES `collection_visits`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
ALTER TABLE `local_profiles` ADD `rete_percent` real DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE `local_profiles` ADD `exercise_percent` real DEFAULT 50 NOT NULL;