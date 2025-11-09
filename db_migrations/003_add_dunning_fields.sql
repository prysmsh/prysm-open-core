-- Migration: Add dunning management fields to subscriptions table
-- Version: 003
-- Description: Adds payment failure tracking and retry scheduling fields
-- Date: 2025-10-22

-- Add dunning management fields
ALTER TABLE subscriptions 
  ADD COLUMN IF NOT EXISTS payment_failure_count INTEGER DEFAULT 0 NOT NULL,
  ADD COLUMN IF NOT EXISTS last_payment_failure TIMESTAMP,
  ADD COLUMN IF NOT EXISTS next_retry_date TIMESTAMP,
  ADD COLUMN IF NOT EXISTS grace_period_end TIMESTAMP;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_subscriptions_payment_failure ON subscriptions(payment_failure_count);
CREATE INDEX IF NOT EXISTS idx_subscriptions_next_retry_date ON subscriptions(next_retry_date);
CREATE INDEX IF NOT EXISTS idx_subscriptions_grace_period_end ON subscriptions(grace_period_end);

-- Add comment
COMMENT ON COLUMN subscriptions.payment_failure_count IS 'Number of consecutive payment failures (resets on successful payment)';
COMMENT ON COLUMN subscriptions.last_payment_failure IS 'Timestamp of most recent payment failure';
COMMENT ON COLUMN subscriptions.next_retry_date IS 'Scheduled date for next automatic payment retry';
COMMENT ON COLUMN subscriptions.grace_period_end IS 'End of grace period after which service will be suspended';

