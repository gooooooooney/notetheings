"use client";

import * as React from "react";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { type ThemeProviderProps } from "next-themes/dist/types";
import { TooltipProvider } from "./ui/tooltip";

export function Providers({ children, ...props }: ThemeProviderProps) {
  return <NextThemesProvider {...props}>
    <TooltipProvider>
      {children}
    </TooltipProvider>
  </NextThemesProvider>;
}