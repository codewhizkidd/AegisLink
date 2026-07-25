"use client";
import React from "react";
import Image from "next/image";
import { FooterBackgroundGradient, TextHoverEffect } from "@/components/ui/hover-footer";

const footerLinks = [
  {
    title: "Product",
    links: [
      { label: "How It Works", href: "#how-it-works" },
      { label: "Scan a URL", href: "#scan" },
      { label: "Threat Guide", href: "#threats" },
    ],
  },
  {
    title: "Project",
    links: [
      { label: "Source Code", href: "https://github.com/afraa786/CyberThreat" },
      { label: "Report an Issue", href: "https://github.com/afraa786/CyberThreat/issues" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="bg-black relative h-fit overflow-hidden border-t border-[var(--border)]">
      <div className="max-w-7xl mx-auto p-8 md:p-14 z-40 relative">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 md:gap-8 lg:gap-16 pb-12">
          <div className="flex flex-col space-y-4">
            <Image src="/logo.png" alt="ASTRO" width={160} height={160} className="w-40 h-auto object-contain" />
            <p className="text-sm leading-relaxed text-white">
              Real-time phishing URL detection powered by a trained ML classifier
              and structural heuristics.
            </p>
          </div>

          {footerLinks.map((section) => (
            <div key={section.title}>
              <h4 className="text-white text-lg font-semibold mb-6">{section.title}</h4>
              <ul className="space-y-3">
                {section.links.map((link) => (
                  <li key={link.label}>
                    <a
                      href={link.href}
                      target={link.href.startsWith("http") ? "_blank" : undefined}
                      rel={link.href.startsWith("http") ? "noreferrer" : undefined}
                      className="text-white hover:text-[#ff3b3b] transition-colors"
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}

          <div>
            <h4 className="text-white text-lg font-semibold mb-6">Built With</h4>
            <ul className="space-y-3 text-white">
              <li>Gradient Boosting Classifier</li>
              <li>WHOIS Domain Intelligence</li>
              <li>Flask + Next.js</li>
            </ul>
          </div>
        </div>

        <hr className="border-t border-[var(--border)] my-8" />

        <div className="flex flex-col md:flex-row justify-between items-center text-sm space-y-4 md:space-y-0">
          <div className="flex space-x-6 text-white">
            <a
              href="https://github.com/afraa786/CyberThreat"
              target="_blank"
              rel="noreferrer"
              aria-label="GitHub"
              className="hover:text-[#ff3b3b] transition-colors"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.09 3.29 9.4 7.86 10.93.57.1.78-.25.78-.55 0-.27-.01-1.17-.02-2.12-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.55-.29-5.23-1.28-5.23-5.68 0-1.25.45-2.28 1.18-3.08-.12-.29-.51-1.46.11-3.04 0 0 .96-.31 3.15 1.18a10.9 10.9 0 0 1 5.73 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.58.23 2.75.11 3.04.73.8 1.18 1.83 1.18 3.08 0 4.41-2.69 5.38-5.25 5.67.42.36.78 1.07.78 2.16 0 1.56-.02 2.82-.02 3.2 0 .3.21.66.79.55A10.5 10.5 0 0 0 23.5 12c0-6.35-5.15-11.5-11.5-11.5Z" />
              </svg>
            </a>
          </div>

          <p className="text-center md:text-left text-white">
            &copy; {new Date().getFullYear()} ASTRO. All rights reserved.
          </p>
        </div>
      </div>

      <div className="lg:flex hidden h-[24rem] -mt-40 -mb-28">
        <TextHoverEffect text="ASTRO" className="z-50" />
      </div>

      <FooterBackgroundGradient />
    </footer>
  );
}
