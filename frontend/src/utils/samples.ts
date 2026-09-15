/**
 * Real manifest fixtures that can be sent directly to POST /api/analyze.
 * No mock backend data is used; these are serialized into real File/Blob objects
 * and sent across the HTTP multipart boundary.
 */

export interface SampleManifest {
  id: string;
  name: string;
  description: string;
  packageJson: string;
  packageLockJson?: string;
}

export const SAMPLE_MANIFESTS: SampleManifest[] = [
  {
    id: 'deep-chain',
    name: 'Multi-tier Service (Express + Axios)',
    description: 'Real 3-tier dependency tree (express -> body-parser -> bytes) with direct and dev dependencies.',
    packageJson: JSON.stringify(
      {
        name: 'cloud-api-service',
        version: '1.0.0',
        dependencies: {
          express: '^4.18.2',
          axios: '^1.6.0',
        },
        devDependencies: {
          jest: '^29.7.0',
        },
      },
      null,
      2
    ),
    packageLockJson: JSON.stringify(
      {
        name: 'cloud-api-service',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': {
            name: 'cloud-api-service',
            version: '1.0.0',
            dependencies: {
              axios: '^1.6.0',
              express: '^4.18.2',
            },
            devDependencies: {
              jest: '^29.7.0',
            },
          },
          'node_modules/axios': {
            version: '1.6.7',
            resolved: 'https://registry.npmjs.org/axios/-/axios-1.6.7.tgz',
            dependencies: {
              'follow-redirects': '^1.15.4',
            },
          },
          'node_modules/body-parser': {
            version: '1.20.2',
            resolved: 'https://registry.npmjs.org/body-parser/-/body-parser-1.20.2.tgz',
            dependencies: {
              bytes: '3.1.2',
            },
          },
          'node_modules/bytes': {
            version: '3.1.2',
            resolved: 'https://registry.npmjs.org/bytes/-/bytes-3.1.2.tgz',
          },
          'node_modules/express': {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            dependencies: {
              'body-parser': '1.20.1',
            },
          },
          'node_modules/follow-redirects': {
            version: '1.15.5',
            resolved: 'https://registry.npmjs.org/follow-redirects/-/follow-redirects-1.15.5.tgz',
          },
          'node_modules/jest': {
            version: '29.7.0',
            resolved: 'https://registry.npmjs.org/jest/-/jest-29.7.0.tgz',
            dev: true,
            dependencies: {
              'jest-cli': '^29.7.0',
            },
          },
          'node_modules/jest-cli': {
            version: '29.7.0',
            resolved: 'https://registry.npmjs.org/jest-cli/-/jest-cli-29.7.0.tgz',
            dev: true,
          },
        },
      },
      null,
      2
    ),
  },
  {
    id: 'osv-vulnerable',
    name: 'Vulnerable Supply Chain (Lodash 4.17.15 + Is-Odd)',
    description: 'Includes lodash@4.17.15 (triggers 6 real live OSV advisories and contextual risk) plus clean is-odd.',
    packageJson: JSON.stringify(
      {
        name: 'payment-gateway',
        version: '2.1.0',
        dependencies: {
          lodash: '4.17.15',
          'is-odd': '3.0.1',
        },
      },
      null,
      2
    ),
    packageLockJson: JSON.stringify(
      {
        name: 'payment-gateway',
        version: '2.1.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': {
            name: 'payment-gateway',
            version: '2.1.0',
            dependencies: {
              'is-odd': '3.0.1',
              lodash: '4.17.15',
            },
          },
          'node_modules/is-odd': {
            version: '3.0.1',
            resolved: 'https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz',
          },
          'node_modules/lodash': {
            version: '4.17.15',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz',
          },
        },
      },
      null,
      2
    ),
  },
  {
    id: 'no-lockfile',
    name: 'Unresolved Manifest (package.json only)',
    description: 'No lockfile provided. Demonstrates fallback to direct_dependencies_only mode.',
    packageJson: JSON.stringify(
      {
        name: 'legacy-web-app',
        version: '0.9.0',
        dependencies: {
          lodash: '^4.17.21',
          chalk: '^5.3.0',
        },
        devDependencies: {
          eslint: '^8.57.0',
        },
      },
      null,
      2
    ),
  },
];
