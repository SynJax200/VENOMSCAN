import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium tracking-wide transition-colors",
  {
    variants: {
      variant: {
        default: "border-line bg-white/5 text-slate-600",
        brand: "border-brand-ring/25 bg-brand/10 text-brand-ring",
        success: "border-emerald-400/25 bg-emerald-500/10 text-emerald-300",
        warning: "border-amber-400/25 bg-amber-500/10 text-amber-300",
        danger: "border-red-400/25 bg-red-500/10 text-red-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  tone?: string;
}

function Badge({ className, variant, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), tone, className)} {...props} />;
}

export { Badge, badgeVariants };
