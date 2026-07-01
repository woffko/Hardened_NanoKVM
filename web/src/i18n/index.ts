import i18n from 'i18next';
import type { Resource } from 'i18next';
import { initReactI18next } from 'react-i18next';

import { getLanguage } from '@/lib/localstorage.ts';

import { applyLocaleExtras } from './locale-extras';

function getResources(): Resource {
  const resources: Resource = {};

  const modules: Record<string, Resource> = import.meta.glob('./locales/*.ts', { eager: true });

  for (const path in modules) {
    const moduleName = path.split('/').pop()?.replace('.ts', '');
    if (moduleName) {
      const resource = modules[path].default;
      applyLocaleExtras(moduleName, resource);
      resources[moduleName] = resource;
    }
  }

  return resources;
}

const languageAliases: Record<string, string> = {
  cs: 'cz',
  nb: 'no',
  nn: 'no',
  se: 'sv',
  'pt-br': 'pt_br',
  pt: 'pt_br',
  'zh-hant': 'zh_tw',
  'zh-hk': 'zh_tw',
  'zh-mo': 'zh_tw',
  'zh-tw': 'zh_tw',
  'zh-cn': 'zh',
  'zh-hans': 'zh',
  'zh-sg': 'zh'
};

function normalizeLanguageCode(language?: string | null) {
  if (!language) return '';

  const normalized = language.trim().replace(/_/g, '-').toLowerCase();
  if (languageAliases[normalized]) return languageAliases[normalized];

  const base = normalized.split('-')[0];
  return languageAliases[base] || base;
}

function getCurrentLanguage(): string {
  const languages = Object.keys(resources);

  const cookieLng = normalizeLanguageCode(getLanguage());
  if (cookieLng && languages.includes(cookieLng)) {
    return cookieLng;
  }

  const navigatorLng = normalizeLanguageCode(navigator.language);
  if (languages.includes(navigatorLng)) {
    return navigatorLng;
  }

  return 'en';
}

const resources = getResources();
const lng = getCurrentLanguage();

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false
    }
  })
  .then();

export default i18n;
