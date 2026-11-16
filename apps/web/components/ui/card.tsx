import * as React from "react";

import { cn } from "@/lib/utils";

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("neon-card rounded-card border border-line bg-panel shadow-card", className)}
      {...props}
    />
  ),
);
Card.displayName = "Card";

const CardTitle = React.forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h2 ref={ref} className={cn("text-[15px] font-semibold text-ink", className)} {...props} />
  ),
);
CardTitle.displayName = "CardTitle";

const CardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p ref={ref} className={cn("mt-0.5 text-[13px] text-slate-500", className)} {...props} />
));
CardDescription.displayName = "CardDescription";

const CardHeader = React.forwardRef<
  HTMLDivElement,
  Omit<React.HTMLAttributes<HTMLDivElement>, "title"> & {
    title?: React.ReactNode;
    subtitle?: React.ReactNode;
    action?: React.ReactNode;
  }
>(({ className, title, subtitle, action, children, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-start justify-between gap-4 border-b border-line px-5 py-4", className)}
    {...props}
  >
    <div>
      {title ? <CardTitle>{title}</CardTitle> : null}
      {subtitle ? <CardDescription>{subtitle}</CardDescription> : null}
      {children}
    </div>
    {action ? <div className="shrink-0">{action}</div> : null}
  </div>
));
CardHeader.displayName = "CardHeader";

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => <div ref={ref} className={cn("px-5 py-4", className)} {...props} />,
);
CardContent.displayName = "CardContent";

export { Card, CardContent, CardDescription, CardHeader, CardTitle };
