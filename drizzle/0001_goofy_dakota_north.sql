CREATE TABLE `import_batches` (
	`id` text PRIMARY KEY NOT NULL,
	`fingerprint` text NOT NULL,
	`imported_at` text NOT NULL,
	`imported_by` text NOT NULL,
	`row_count` integer NOT NULL,
	`local_count` integer NOT NULL,
	FOREIGN KEY (`imported_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `import_batches_fingerprint_unique` ON `import_batches` (`fingerprint`);--> statement-breakpoint
CREATE TABLE `local_profiles` (
	`local_key` text PRIMARY KEY NOT NULL,
	`local_code` text DEFAULT '' NOT NULL,
	`pdv_code` text DEFAULT '' NOT NULL,
	`name` text NOT NULL,
	`address` text DEFAULT '' NOT NULL,
	`comune` text DEFAULT '' NOT NULL,
	`provincia` text DEFAULT '' NOT NULL,
	`ragione_sociale` text DEFAULT '' NOT NULL,
	`insegna` text DEFAULT '' NOT NULL,
	`partita_iva` text DEFAULT '' NOT NULL,
	`codice_fiscale` text DEFAULT '' NOT NULL,
	`contact_name` text DEFAULT '' NOT NULL,
	`phone` text DEFAULT '' NOT NULL,
	`email` text DEFAULT '' NOT NULL,
	`pec` text DEFAULT '' NOT NULL,
	`notes` text DEFAULT '' NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `machine_history` (
	`id` text PRIMARY KEY NOT NULL,
	`machine_id` text NOT NULL,
	`import_id` text NOT NULL,
	`local_key` text NOT NULL,
	`local` text NOT NULL,
	`local_code` text DEFAULT '' NOT NULL,
	`comune` text DEFAULT '' NOT NULL,
	`address` text DEFAULT '' NOT NULL,
	`model` text DEFAULT '' NOT NULL,
	`code_model` text DEFAULT '' NOT NULL,
	`code_provv` text DEFAULT '' NOT NULL,
	`status` text DEFAULT '' NOT NULL,
	`cnt_in` text DEFAULT '' NOT NULL,
	`cnt_out` text DEFAULT '' NOT NULL,
	`exercise_code` text DEFAULT '' NOT NULL,
	`pda_mac` text DEFAULT '' NOT NULL,
	`read_at` text NOT NULL,
	`raw_json` text DEFAULT '{}' NOT NULL,
	FOREIGN KEY (`import_id`) REFERENCES `import_batches`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
ALTER TABLE `machines` ADD `local_key` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `local_code` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `provincia` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `pdv_code` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `pda_mac` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `hopper1` real DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `hopper2` real DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `machines` ADD `last_import_id` text DEFAULT '' NOT NULL;