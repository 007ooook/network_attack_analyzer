import React, { useState } from 'react';
import { Card, Form, Input, Button, message } from 'antd';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';

const { TextArea } = Input;

const LogParser: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();
  const { t } = useTranslation();

  // 解析日志
  const handleParse = async (values: any) => {
    setLoading(true);
    try {
      const response = await api.post('/parse', values.logs, {
        headers: {
          'Content-Type': 'text/plain'
        }
      });
      const parsedCount = response.data?.parsed?.length || 0;
      message.success(t('logParser.parseSuccess', { count: parsedCount }));
      // 清空表单
      form.resetFields();
    } catch (error) {
      console.error('Error parsing logs:', error);
      message.error(t('logParser.parseError'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card title={t('logParser.title')} style={{ marginBottom: '20px' }}>
      <Form form={form} onFinish={handleParse} className="form-container">
        <Form.Item name="logs" label={t('logParser.inputLabel')}>
          <TextArea rows={10} placeholder={t('logParser.placeholder')} />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            {t('logParser.parseButton')}
          </Button>
        </Form.Item>
      </Form>
    </Card>
  );
};

export default LogParser;
