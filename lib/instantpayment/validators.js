import Joi from "joi";

const VatSchema = Joi.object({
    amount: Joi.number().positive().optional(),
    rate: Joi.string()
        .pattern(/^[0-9]{0,2}$/)
        .optional(),
    type: Joi.string()
        .valid('INCLUDED', 'NO_VAT', 'MANUAL')
        .required()
        .messages({
            'any.only': '"type" должен быть одним из: INCLUDED, NO_VAT, MANUAL',
            'any.required': '"type" обязателен'
        })
});

const LinkedDocSchema = Joi.object({
    /**
     * Идентификатор документа (UUID)
     */
    docExtId: Joi.string()
        .guid({ version: 'uuidv4' })
        .required()
        .messages({
            'string.guid': '"docExtId" должен быть валидным UUID v4',
            'any.required': '"docExtId" обязателен'
        }),

    /**
     * Тип документа (по умолчанию "ExportContractInsure")
     */
    type: Joi.string()
        .valid('ExportContractInsure')
        .default('ExportContractInsure')
        .optional()
});

export const paymentInvoiceReqSchema = Joi.object({
    /**
     * Идентификатор документа, присвоенный партнером
     */
    externalId: Joi.string().min(1).required().messages({
        'string.empty': '"externalId" обязателен',
        'any.required': '"externalId" обязателен'
    }),

    /**
     * Сумма платежа
     */
    amount: Joi.number().positive().required().messages({
        'number.base': '"amount" должно быть числом',
        'number.positive': '"amount" должно быть больше нуля',
        'any.required': '"amount" обязательно'
    }),

    /**
     * Дата составления документа
     */
    date: Joi.string()
        .pattern(/^\d{4}-\d{2}-\d{2}$/)
        .required()
        .messages({
            'string.pattern.base': '"date" должна быть в формате YYYY-MM-DD',
            'any.required': '"date" обязательна'
        }),

    /**
     * Назначение платежа (до 240 символов)
     */
    purpose: Joi.string().max(240).optional(),

    /**
     * Счет получателя платежа
     */
    payeeAccount: Joi.string().min(1).required().messages({
        'string.empty': '"payeeAccount" обязателен',
        'any.required': '"payeeAccount" обязателен'
    }),

    /**
     * Код срочности.
     *
     * INTERNAL - срочный
     * INTERNAL_NOTIF - срочный платеж с уведомлением
     * OFFHOURS - неотложный
     * BESP - банковские электронные срочные платежи
     * NORMAL - срочность не указана
     */
    urgencyCode: Joi.string()
        .valid('INTERTAL', 'INTERNAL_NOTIF', 'OFFHOURS', 'BESP', 'NORMAL')
        .optional()
        .messages({
            'any.only':
                '"urgencyCode" должен быть одним из: INTERTAL, INTERNAL_NOTIF, OFFHOURS, BESP, NORMAL'
        }),

    /**
     * Номер платежного поручения
     */
    paymentNumber: Joi.string()
        .pattern(/^[0-9]{1,6}$/)
        .optional()
        .messages({
            'string.pattern.base': '"paymentNumber" должен содержать от 1 до 6 цифр'
        }),

    /**
     * Вид платежа
     */
    deliveryKind: Joi.string()
        .valid('электронно', 'срочно', '0')
        .optional()
        .messages({
            'any.only': '"deliveryKind" должен быть одним из: электронно, срочно, 0'
        }),

    /**
     * Дата истечения заказа (платеж должен быть подтвержден клиентом)
     */
    expirationDate: Joi.string()
        .pattern(/^\d{4}-\d{2}-\d{2}$/)
        .optional()
        .messages({
            'string.pattern.base': '"expirationDate" должна быть в формате YYYY-MM-DD'
        }),

    /**
     * Код операции
     */
    operationCode: Joi.string()
        .pattern(/^01$/)
        .optional()
        .messages({
            'string.pattern.base': '"operationCode" должен быть "01"'
        }),

    /**
     * Связанные документы
     */
    linkedDocs: Joi.array().items(LinkedDocSchema).optional(),

    /**
     * Номер заказа
     */
    orderNumber: Joi.string().optional(),

    /**
     * Очередность платежа
     */
    priority: Joi.string()
        .pattern(/^[4-5]$/)
        .optional()
        .messages({
            'string.pattern.base': '"priority" должен быть 4 или 5'
        }),

    /**
     * Данные НДС
     */
    vat: VatSchema.optional(),

    /**
     * Идентификатор получателя платежа
     */
    payeeOrgIdHash: Joi.string()
        .pattern(/^[0-9a-f]{64}$/i)
        .optional()
        .messages({
            'string.pattern.base': '"payeeOrgIdHash" должен быть 64-значным шестнадцатеричным числом'
        })
});

export const DepartmentalInfoSchema = Joi.object({
    /**
     * Уникальный идентификатор платежа (реквизит - 101)
     */
    uip: Joi.string().min(1).messages({
        'string.empty': '"uip" обязателен',
    }),

    /**
     * Показатель статуса налогоплательщика (реквизит - 101)
     */
    drawerStatus101: Joi.string().min(1).messages({
        'string.empty': '"drawerStatus101" обязателен',
    }),

    /**
     * Код бюджетной классификации (реквизит - 104)
     */
    kbk: Joi.string().min(1).messages({
        'string.empty': '"kbk" обязателен',
    }),

    /**
     * Код ОКТМО (реквизит - 105)
     */
    oktmo: Joi.string().min(1).messages({
        'string.empty': '"oktmo" обязателен',
    }),

    /**
     * Номер документа (реквизит - 108)
     */
    docNumber108: Joi.string().min(1).messages({
        'string.empty': '"docNumber108" обязателен',
    }),

    /**
     * Основание платежа (реквизит - 106)
     */
    reasonCode106: Joi.string().min(1).messages({
        'string.empty': '"reasonCode106" обязателен',
    }),

    /**
     * Налоговый период / код таможенного органа (реквизит - 107)
     */
    taxPeriod107: Joi.string().min(1).messages({
        'string.empty': '"taxPeriod107" обязателен',
    }),

    /**
     * Тип налогового платежа (реквизит - 110)
     */
    paymentKind110: Joi.string().min(1).optional()
});

const paymentInvoiceBudgetReqSchema = paymentInvoiceReqSchema.keys({
    /**
     * Реквизиты налогового, таможенного или иного бюджетного платежа
     */
    departmentalInfo: DepartmentalInfoSchema.required().messages({
        'any.required': '"departmentalInfo" обязателен'
    }),

    /**
     * БИК банка получателя платежа
     */
    payeeBankBic: Joi.string()
        .pattern(/^[0-9]{9}$/)
        .required()
        .messages({
            'string.pattern.base': '"payeeBankBic" должен содержать ровно 9 цифр',
            'any.required': '"payeeBankBic" обязателен'
        }),

    /**
     * Кор. счет банка получателя платежа
     */
    payeeBankCorrAccount: Joi.string()
        .pattern(/^[0-9]{20}$/)
        .optional()
        .messages({
            'string.pattern.base': '"payeeBankCorrAccount" должен содержать ровно 20 цифр'
        }),

    /**
     * ИНН получателя платежа
     */
    payeeInn: Joi.string()
        .pattern(/^([0-9]{5}|[0-9]{10}|[0-9]{12}|0)$/)
        .required()
        .messages({
            'string.pattern.base': '"payeeInn" должен соответствовать формату',
            'any.required': '"payeeInn" обязателен'
        }),

    /**
     * КПП получателя платежа
     */
    payeeKpp: Joi.string()
        .pattern(/^([0-9]{9}|0)$/)
        .optional()
        .messages({
            'string.pattern.base': '"payeeKpp" должен быть 9 цифр или "0"'
        }),

    /**
     * Наименование получателя платежа
     */
    payeeName: Joi.string()
        .min(1)
        .required()
        .messages({
            'string.empty': '"payeeName" обязателен',
            'any.required': '"payeeName" обязателен'
        })
});

export const paymentInvoiceFromAnyRequestSchema = paymentInvoiceReqSchema.keys({
    /**
     * Номер кредитного договора
     */
    creditContractNumber: Joi.string().optional(),

    /**
     * Признак того, что платежное поручение будет оплачено за счет кредитных средств
     */
    isPaidByCredit: Joi.boolean().required().messages({
        'boolean.base': '"isPaidByCredit" должно быть булевым значением',
        'any.required': '"isPaidByCredit" обязательно'
    }),

    /**
     * БИК банка получателя платежа
     */
    payeeBankBic: Joi.string()
        .pattern(/^[0-9]{9}$/)
        .required()
        .messages({
            'string.pattern.base': '"payeeBankBic" должен содержать ровно 9 цифр',
            'any.required': '"payeeBankBic" обязателен'
        }),

    /**
     * Кор. счет банка получателя платежа
     */
    payeeBankCorrAccount: Joi.string()
        .pattern(/^[0-9]{20}$/)
        .optional()
        .messages({
            'string.pattern.base': '"payeeBankCorrAccount" должен содержать ровно 20 цифр'
        }),

    /**
     * ИНН получателя платежа
     */
    payeeInn: Joi.string()
        .pattern(/^([0-9]{5}|[0-9]{10}|[0-9]{12}|0)$/)
        .required()
        .messages({
            'string.pattern.base': '"payeeInn" должен соответствовать формату',
            'any.required': '"payeeInn" обязателен'
        }),

    /**
     * КПП получателя платежа
     */
    payeeKpp: Joi.string()
        .pattern(/^([0-9]{9}|0)$/)
        .optional()
        .messages({
            'string.pattern.base': '"payeeKpp" должен быть 9 цифр или "0"'
        }),

    /**
     * Наименование получателя платежа
     */
    payeeName: Joi.string()
        .min(1)
        .required()
        .messages({
            'string.empty': '"payeeName" обязателен',
            'any.required': '"payeeName" обязателен',
            'string.pattern.base': '"payeeName" может содержать до 254 символов'
        })
});

export default { paymentInvoiceReqSchema, paymentInvoiceBudgetReqSchema, paymentInvoiceFromAnyRequestSchema }
