import { useState, useEffect } from 'react';
import { Card, Table, Button, Modal, Form, Input, Select, Switch, message, Space, Popconfirm, Typography, Tag } from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { api } from '../utils/api';

const { TextArea } = Input;
const { Option } = Select;
const { Title } = Typography;

interface Rule {
  rule_id: string;
  name: string;
  description: string;
  severity: string;
  enabled: boolean;
  conditions: any;
  actions: string[];
}

export default function RulesManager() {
  const { t } = useTranslation();
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [form] = Form.useForm();

  // 加载规则列表
  const loadRules = async () => {
    try {
      setLoading(true);
      const response = await api.get('/rules');
      const data = response.data;
      
      if (data.error) {
        message.error(data.error);
        setRules([]);
      } else {
        setRules(data.rules || []);
      }
    } catch (err) {
      message.error(t('common.error'));
    } finally {
      setLoading(false);
    }
  };

  // 初始化加载
  useEffect(() => {
    loadRules();
  }, []);

  // 打开添加规则模态框
  const showAddModal = () => {
    form.resetFields();
    setEditingRule(null);
    setIsModalVisible(true);
  };

  // 打开编辑规则模态框
  const showEditModal = (rule: Rule) => {
    setEditingRule(rule);
    form.setFieldsValue({
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      enabled: rule.enabled,
      conditions: JSON.stringify(rule.conditions, null, 2),
      actions: rule.actions.join(', ')
    });
    setIsModalVisible(true);
  };

  // 保存规则
  const handleSave = async () => {
    try {
      const values = await form.validateFields();
      
      const ruleData = {
        name: values.name,
        description: values.description,
        severity: values.severity,
        enabled: values.enabled,
        conditions: JSON.parse(values.conditions),
        actions: values.actions.split(',').map((action: string) => action.trim())
      };

      let response;
      if (editingRule) {
        // 更新规则
        response = await api.put(`/rules/${editingRule.rule_id}`, ruleData);
      } else {
        // 添加规则
        response = await api.post('/rules', ruleData);
      }

      if (response.data.error) {
        message.error(response.data.error);
      } else {
        message.success(editingRule ? '规则更新成功' : '规则添加成功');
        setIsModalVisible(false);
        loadRules();
      }
    } catch (err) {
      message.error('保存规则失败');
    }
  };

  // 删除规则
  const handleDelete = async (rule_id: string) => {
    try {
      const response = await api.delete(`/rules/${rule_id}`);
      if (response.data.error) {
        message.error(response.data.error);
      } else {
        message.success('规则删除成功');
        loadRules();
      }
    } catch (err) {
      message.error('删除规则失败');
    }
  };

  // 启用/禁用规则
  const handleToggleRule = async (rule_id: string, enabled: boolean) => {
    try {
      const response = await api.patch(`/rules/${rule_id}/status`, {
        enabled: !enabled
      });
      if (response.data.error) {
        message.error(response.data.error);
      } else {
        message.success(enabled ? '规则已禁用' : '规则已启用');
        loadRules();
      }
    } catch (err) {
      message.error('操作失败');
    }
  };

  // 列定义
  const columns = [
    {
      title: '规则ID',
      dataIndex: 'rule_id',
      key: 'rule_id',
      width: 160,
      render: (text: string) => (
        <Tag color="geekblue" style={{ fontFamily: 'monospace' }}>{text}</Tag>
      ),
    },
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity: string) => {
        let color = 'blue';
        if (severity === 'Critical') color = 'red';
        if (severity === 'High') color = 'orange';
        if (severity === 'Medium') color = 'yellow';
        if (severity === 'Low') color = 'green';
        return <Tag color={color}>{severity}</Tag>;
      },
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      render: (enabled: boolean, record: Rule) => (
        <Switch 
          checked={enabled} 
          onChange={() => handleToggleRule(record.rule_id, enabled)}
        />
      ),
    },
    {
      title: '动作',
      key: 'actions',
      render: (_: any, record: Rule) => (
        <Space size="middle">
          <Button 
            type="primary" 
            icon={<EditOutlined />} 
            onClick={() => showEditModal(record)}
          />
          <Popconfirm
            title="确定要删除此规则吗？"
            onConfirm={() => handleDelete(record.rule_id)}
            okText="确定"
            cancelText="取消"
          >
            <Button danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div className="rules-manager">
      <Card
        title={
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Title level={4} style={{ margin: 0 }}>规则管理</Title>
            <Space>
              <Button 
                icon={<ReloadOutlined />} 
                onClick={loadRules}
                loading={loading}
              >
                刷新
              </Button>
              <Button 
                type="primary" 
                icon={<PlusOutlined />} 
                onClick={showAddModal}
              >
                添加规则
              </Button>
            </Space>
          </div>
        }
        bordered={false}
      >
        <Table 
          columns={columns} 
          dataSource={rules} 
          rowKey="rule_id" 
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条规则`,
          }}
        />
      </Card>

      <Modal
        title={editingRule ? '编辑规则' : '添加规则'}
        open={isModalVisible}
        onOk={handleSave}
        onCancel={() => setIsModalVisible(false)}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            severity: 'Medium',
            enabled: true,
            conditions: JSON.stringify({},
  null, 2),
            actions: 'alert'
          }}
        >
          <Form.Item
            name="name"
            label="规则名称"
            rules={[{ required: true, message: '请输入规则名称' }]}
          >
            <Input placeholder="请输入规则名称" />
          </Form.Item>

          <Form.Item
            name="description"
            label="规则描述"
            rules={[{ required: true, message: '请输入规则描述' }]}
          >
            <TextArea rows={3} placeholder="请输入规则描述" />
          </Form.Item>

          <Form.Item
            name="severity"
            label="严重程度"
            rules={[{ required: true, message: '请选择严重程度' }]}
          >
            <Select placeholder="请选择严重程度">
              <Option value="Critical">Critical</Option>
              <Option value="High">High</Option>
              <Option value="Medium">Medium</Option>
              <Option value="Low">Low</Option>
            </Select>
          </Form.Item>

          <Form.Item
            name="enabled"
            label="启用状态"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>

          <Form.Item
            name="conditions"
            label="规则条件 (JSON 格式)"
            rules={[{ required: true, message: '请输入规则条件' }]}
          >
            <TextArea rows={6} placeholder='例如: {"attack_type": {"in": ["SQL Injection"]}, "confidence": {"min": 0.7}}' />
          </Form.Item>

          <Form.Item
            name="actions"
            label="规则动作 (逗号分隔)"
            rules={[{ required: true, message: '请输入规则动作' }]}
          >
            <Input placeholder="例如: alert, block_ip, notify_admin" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
