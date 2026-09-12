import {
  ArrowsLeftRight,
  Crosshair,
  Desktop,
  Globe,
  type Icon,
  Plugs,
  Question,
  ShieldCheck,
} from "@phosphor-icons/react";

/** The Aegis mark: a shield that deflects, drawn as a single aegis scale. Passive by design. */
export function AegisMark({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2.5 20 5.6v6.1c0 4.7-3.2 8.6-8 9.8-4.8-1.2-8-5.1-8-9.8V5.6L12 2.5Z" fill="currentColor" opacity="0.28" />
      <path
        d="M12 2.5 20 5.6v6.1c0 4.7-3.2 8.6-8 9.8-4.8-1.2-8-5.1-8-9.8V5.6L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="M12 7.6v8.8M8.4 9.8v4.4M15.6 9.8v4.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

export function BrandLockup() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <AegisMark size={19} />
      </span>
      <span className="brand-name">
        Aegis <span>OT</span>
      </span>
    </div>
  );
}

/**
 * The five entity kinds in schemas/alert.v1.schema.json. Each keys a different kind of
 * thing - a host, a service endpoint, a conversation, a domain - so each gets its own
 * glyph rather than one generic host icon.
 */
const ENTITY_ICONS: Record<string, Icon> = {
  src_host: Desktop,
  dst_host: Crosshair,
  dst_service: Plugs,
  service_pair: ArrowsLeftRight,
  src_domain: Globe,
};

export function entityIcon(kind: string): Icon {
  return ENTITY_ICONS[kind.toLowerCase()] ?? Question;
}

export { ShieldCheck };
