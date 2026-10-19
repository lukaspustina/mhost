/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'mhost',
  tagline: 'A modern, high-performance DNS Swiss Army knife and Rust library.',
  url: 'https://mhost.pustina.de',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  favicon: 'img/favicon.ico',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },
  organizationName: 'lukaspustina',
  projectName: 'mhost',

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        blog: false,
        docs: {
          sidebarPath: './sidebars.js',
          editUrl:
            'https://github.com/lukaspustina/mhost/edit/master/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'mhost',
      logo: {
        alt: 'mhost',
        src: 'img/logo_blue.svg',
      },
      items: [
        {
          to: 'docs/',
          label: 'Docs',
          position: 'left',
        },
        {
          href: 'https://github.com/lukaspustina/mhost',
          className: 'header-github-link',
          position: 'right',
          'aria-label': 'GitHub repository',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'API',
              href: 'https://docs.rs/mhost/',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub Issues',
              href: 'https://github.com/lukaspustina/mhost/issues',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Crates.io',
              href: 'https://crates.io/crates/mhost',
            },
            {
              label: 'GitHub',
              href: 'https://github.com/lukaspustina/mhost',
            },
          ],
        },
        {
          title: 'Legal Stuff',
          items: [
            {
              label: 'Legal Notice',
              href: 'https://lukas.pustina.de/legal_notice/',
            },
            {
              label: 'Privacy Policy',
              href: 'https://lukas.pustina.de/privacy_policy/',
            },
            {
              label: 'Image Attributions',
              to: 'docs/attributions_images/',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Lukas Pustina`,
    },
  },
};

module.exports = config;
