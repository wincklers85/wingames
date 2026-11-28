CREATE TABLE `day_closings` (
	`id` text PRIMARY KEY NOT NULL,
	`day` text NOT NULL,
	`status` text DEFAULT 'closed' NOT NULL,
	`closed_at` text NOT NULL,
	`closed_by` text NOT NULL,
	`closed_by_name` text NOT NULL,
	`totals_json` text DEFAULT '{}' NOT NULL,
	FOREIGN KEY (`closed_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
ALTER TABLE `collection_visits` ADD `business_day` text NOT NULL;