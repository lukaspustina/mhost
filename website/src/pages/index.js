import clsx from 'clsx';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import styles from './styles.module.css';

const features = [
  {
    title: 'Query everything, everywhere',
    imageUrl: 'img/fast_reliable_blue.svg',
    description: (
      <>
        Fire queries at up to 10,000 nameservers in parallel. Ships with 84 built-in public resolvers from 6 providers. Add WHOIS with <code>-w</code> to see who's behind every IP.
      </>
    ),
  },
  {
    title: 'All four protocols',
    imageUrl: 'img/classic_modern_blue.svg',
    description: (
      <>
        UDP, TCP, DNS-over-TLS, DNS-over-HTTPS -- because it's not 2005 anymore. 84 pre-configured endpoints across Cloudflare, Google, Quad9, Mullvad, Wikimedia, and DNS4EU.
      </>
    ),
  },
  {
    title: 'Hunt down subdomains',
    imageUrl: 'img/discover_blue.svg',
    description: (
      <>
        10+ discovery strategies chained automatically: CT logs, wordlists, AXFR, NSEC walking, SRV probing, TXT mining, permutation, recursive depth, and reverse DNS.
      </>
    ),
  },
  {
    title: 'Lint your DNS',
    imageUrl: 'img/lint_blue.svg',
    description: (
      <>
        13 lints catch the things you forgot: lame delegation, missing SPF, broken DMARC, exposed zone transfers, open resolvers, DNSSEC gaps, and more.
      </>
    ),
  },
  {
    title: 'Trace, diff, verify, propagate',
    imageUrl: 'img/human_machine_friendly_blue.svg',
    description: (
      <>
        Trace delegation from the root. Visualize DNSSEC trust chains. Diff records between nameservers or snapshots. Verify zone files in CI. Check propagation across the globe.
      </>
    ),
  },
  {
    title: 'Interactive TUI + Rust library',
    imageUrl: 'img/api_blue.svg',
    description: (
      <>
        <code>mdive</code> turns DNS into a browsable, drillable, filterable experience with vi-style keys and real-time discovery. Plus an async Rust library for building your own tools.
      </>
    ),
  },
];

function Feature({imageUrl, title, description, index}) {
  const delayClass = styles[`featureDelay${index}`];
  return (
    <div className={clsx('col col--4', styles.feature)}>
      <div className={clsx(styles.featureCard, delayClass)}>
        {imageUrl && (
          <div className="text--center">
            <img className={styles.featureImage} src={imageUrl} alt={title} />
          </div>
        )}
        <h3 className={styles.featureTitle}>{title}</h3>
        <p className={styles.featureDescription}>{description}</p>
      </div>
    </div>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title="DNS lookup, discovery, linting, and more"
      description="mhost - a modern, high-performance DNS Swiss Army knife and Rust library. Parallel multi-server queries, subdomain discovery, DNS linting, propagation checking, zone file verification, and an interactive TUI.">
      <header className={styles.heroBanner}>
        <div className="container">
          <h1 className={styles.heroTitle}>{siteConfig.title}</h1>
          <p className={styles.heroSubtitle}>{siteConfig.tagline}</p>
          <div className={styles.buttons}>
            <Link
              className={clsx(
                'button button--lg',
                styles.ctaPrimary,
              )}
              to="/docs/installation">
              Get Started
            </Link>
            <Link
              className={clsx(
                'button button--outline button--lg',
                styles.ctaSecondary,
              )}
              to="/docs/usage_examples">
              Examples
            </Link>
            <Link
              className={clsx(
                'button button--outline button--lg',
                styles.ctaSecondary,
              )}
              to="https://github.com/lukaspustina/mhost">
              GitHub
            </Link>
          </div>
        </div>
      </header>
      <main>
        <section>
          <div className={styles.terminalFrame}>
            <div className={styles.terminalBar}>
              <span className={styles.terminalDotRed} />
              <span className={styles.terminalDotYellow} />
              <span className={styles.terminalDotGreen} />
              <span className={styles.terminalTitle}>mhost -- github.com</span>
            </div>
            <div className={styles.terminalBody}>
              <img src="img/multi-lookup-all-records-github.png" alt="mhost looking up all record types for github.com"/>
            </div>
          </div>
        </section>
        {features && features.length > 0 && (
          <section className={styles.features}>
            <div className="container">
              <div className="row">
                {features.map((props, idx) => (
                  <Feature key={idx} index={idx} {...props} />
                ))}
              </div>
            </div>
          </section>
        )}
      </main>
    </Layout>
  );
}
