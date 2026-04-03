import { useTranslation } from 'react-i18next';

export const useLanguage = () => {
  const { t, i18n } = useTranslation();

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  return {
    t,
    i18n,
    changeLanguage,
    currentLanguage: i18n.language,
  };
};
