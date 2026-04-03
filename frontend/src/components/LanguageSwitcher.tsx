import React from 'react';
import { Dropdown, MenuProps, Space } from 'antd';
import { TranslationOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

const LanguageSwitcher: React.FC = () => {
  const { i18n } = useTranslation();

  const currentLanguage = i18n.language === 'zh' ? 'zh' : 'en';

  const items: MenuProps['items'] = [
    {
      key: 'zh',
      label: '中文',
      onClick: () => {
        i18n.changeLanguage('zh');
      },
    },
    {
      key: 'en',
      label: 'English',
      onClick: () => {
        i18n.changeLanguage('en');
      },
    },
  ];

  return (
    <Dropdown menu={{ items }} placement="bottomLeft" arrow>
      <Space style={{ cursor: 'pointer' }}>
        <TranslationOutlined />
        <span>{currentLanguage === 'zh' ? '中文' : 'English'}</span>
      </Space>
    </Dropdown>
  );
};

export default LanguageSwitcher;
