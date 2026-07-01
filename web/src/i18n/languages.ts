const languages = [
  { key: 'ca', name: 'Català' },
  { key: 'da', name: 'Dansk' },
  { key: 'de', name: 'Deutsch' },
  { key: 'en', name: 'English' },
  { key: 'et', name: 'Eesti' },
  { key: 'es', name: 'Español' },
  { key: 'fi', name: 'Suomi' },
  { key: 'fr', name: 'Français' },
  { key: 'id', name: 'Bahasa Indonesia' },
  { key: 'it', name: 'Italiano' },
  { key: 'nl', name: 'Nederlands' },
  { key: 'no', name: 'Norsk' },
  { key: 'pl', name: 'Polski' },
  { key: 'pt_br', name: 'Português (Brasil)' },
  { key: 'ru', name: 'Русский' },
  { key: 'tr', name: 'Türkçe' },
  { key: 'ko', name: '한국어' },
  { key: 'zh', name: '简体中文' },
  { key: 'zh_tw', name: '繁體中文' },
  { key: 'hu', name: 'Magyar' },
  { key: 'vi', name: 'Tiếng Việt' },
  { key: 'ja', name: '日本語' },
  { key: 'cz', name: 'Čeština' },
  { key: 'uk', name: 'Українська' },
  { key: 'th', name: 'ภาษาไทย' },
  { key: 'sv', name: 'Svenska' }
];

languages.sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));

export default languages;
