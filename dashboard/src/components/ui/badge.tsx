import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

/**
 * Severity variants map one-to-one onto the risk levels in spec §19, so a
 * badge colour on screen always means the same thing.
 */
const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary/15 text-primary",
        outline: "border-border text-muted-foreground",
        low: "border-transparent bg-sev-low/15 text-sev-low",
        medium: "border-transparent bg-sev-medium/15 text-sev-medium",
        elevated: "border-transparent bg-sev-elevated/15 text-sev-elevated",
        high: "border-transparent bg-sev-high/15 text-sev-high",
        critical: "border-transparent bg-sev-critical/20 text-sev-critical",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export type BadgeProps = React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants>;

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
