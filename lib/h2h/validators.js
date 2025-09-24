import Joi from 'joi';

const TypeEnum = {
  INCLUDED: 'INCLUDED',
  ONTOP: 'ONTOP',
  NO_VAT: 'NO_VAT',
  MANUAL: 'MANUAL'
};

const certRequestReqSchema = Joi.object({
  email: Joi.string().pattern(/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,}$/).required(),
  externalId: Joi.string().required(),
  number: Joi.string().required(),
  orgName: Joi.string(),
  pkcs10: Joi.object({
    bicryptId: Joi.string().required(),
    cms: Joi.string().required()
  }),
  userName: Joi.string().required(),
  userPosition: Joi.string().required(),
  bankStatus: Joi.string(),
  bankComment: Joi.string()
});

const certRequestReqEIOSchema = Joi.object({
  email: Joi.string().pattern(/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,}$/).required(),
  externalId: Joi.string().required(),
  login: Joi.string().required(),
  number: Joi.string().required(),
  orgName: Joi.string(),
  pkcs10: Joi.object({
    bicryptId: Joi.string().required(),
    cms: Joi.string().required()
  }),
  userName: Joi.string().required(),
  userPosition: Joi.string().required(),
  bankStatus: Joi.string(),
  bankComment: Joi.string()
});

const paymentReqSchema = Joi.object({
  number: Joi.string().pattern(/^[0-9]{1,6}$/).optional(),
  date: Joi.date().iso().required(),
  digestSignatures: Joi.array().items({
    base64Encoded: Joi.string().required(),
    certificateUuid: Joi.string().guid({ version: 'uuidv4' }).required()
  }).optional(),
  bankStatus: Joi.string().optional(),
  bankComment: Joi.string().optional(),
  externalId: Joi.string().guid({ version: 'uuidv4' }).required(),
  amount: Joi.number().precision(2).required(),
  operationCode: Joi.string().pattern(/^01$/).required(),
  deliveryKind: Joi.string().pattern(/^(электронно|срочно|0)$/i).optional(),
  priority: Joi.string().pattern(/^(1|2|3|4|5)$/).required(),
  urgencyCode: Joi.string().valid('INTERTAL', 'INTERNAL_NOTIF', 'OFFHOURS', 'BESP', 'NORMAL').optional(),
  voCode: Joi.string().pattern(/^[0-9]{5}$/).optional(),
  purpose: Joi.string().max(210).required(),
  departmentalInfo: {
    uip: Joi.string()
        .pattern(/^[A-Za-z0-9]{1,25}$/)
        .required(),
    drawerStatus101: Joi.string()
        .pattern(/^(01|02|08|13)$/)
        .required(),
    kbk: Joi.string()
        .pattern(/^[A-Za-z0-9]{1,20}$/)
        .required(),
    oktmo: Joi.string()
        .pattern(/^[A-Za-z0-9]{1,11}$/)
        .required(),
    reasonCode106: Joi.string()
        .pattern(/^[0-9]{1,2}$/)
        .required(),
    taxPeriod107: Joi.string()
        .pattern(/^(0|[0-9]{8}|([0-9]{2}|МС|КВ|ПЛ|ГД)\.[0-9]{2}\.[0-9]{4})$/)
        .required(),
    docNumber108: Joi.string()
        .pattern(/^[0-9]{1,15}$/)
        .required(),
    docDate109: Joi.string()
        .pattern(/^(0|00|[0-9]{2}\.[0-9]{2}\.[0-9]{4})$/)
        .required(),
    paymentKind110: Joi.string()
        .pattern(/^[0-9]{1,2}$/)
        .optional(),
  },
  payerName: Joi.string().max(254).required(),
  payerInn: Joi.string()
      .pattern(/^([0-9]{5}|[0-9]{10}|[0-9]{12}|0)$/)
      .required(),
  payerKpp: Joi.string()
      .pattern(/^([0-9]{9}|0)$/),
  payerAccount: Joi.string().pattern(/^[0-9]{20}$/).required(),
  payerBankBic: Joi.string().pattern(/^[0-9]{9}$/).required(),
  payerBankCorrAccount: Joi.string().pattern(/^[0-9]{20}$/).required(),
  payeeName: Joi.string().max(254).required(),
  payeeInn: Joi.string()
      .pattern(/^([0-9]{5}|[0-9]{10}|[0-9]{12}|0)$/)
      .optional(),
  payeeKpp: Joi.string()
      .pattern(/^([0-9]{9}|0)$/)
      .optional(),
  payeeAccount: Joi.string().pattern(/^[0-9]{20}$/).optional(),
  payeeBankBic: Joi.string().pattern(/^[0-9]{9}$/).required(),
  payeeBankCorrAccount: Joi.string().pattern(/^[0-9]{20}$/).optional(),
  crucialFieldsHash: Joi.string().optional(),
  vat: {
    type: Joi.string()
        .valid(
            TypeEnum.INCLUDED,
            TypeEnum.ONTOP,
            TypeEnum.NO_VAT,
            TypeEnum.MANUAL
        )
        .required(),
    rate: Joi.string()
        .pattern(/^[0-9]{0,2}$/)
        .optional(),
    amount: Joi.number()
        .precision(2)
        .optional()
  },
  incomeTypeCode: Joi.string().pattern(/^[1-9]{1,6}$/).optional(),
  isPaidByCredit: Joi.boolean().optional(),
  creditContractNumber: Joi.string().optional()
});

export const rateSchema = Joi.string()
    .pattern(/^([1-9]\d*|0)(\.\d+)?$/)
    .custom((value, helpers) => {
        const num = parseFloat(value);
        if (isNaN(num) || num < 0.01) {
            return helpers.error('any.invalid');
        }
        return value;
    }, 'String must represent a number >= 0.01')
    .messages({
        'any.invalid': '"actualRate" должно быть числом ≥ 0.01'
    })
    .optional()

export const AmountSchema = Joi.object({
  amount: Joi.number()
      .min(0.01)
      .required()
      .messages({
        'number.min': '"amount" должно быть больше или равно 0.01',
        'any.required': '"amount" обязательно'
      }),

  currencyCode: Joi.string()
      .pattern(/^[A-Z\d]\d{2}$/i)
      .required()
      .messages({
        'string.pattern.base': '"currencyCode" должен соответствовать формату (например, 3 символа: цифра/заглавная буква + 2 цифры)',
        'any.required': '"currencyCode" обязателен'
      }),

  currencyName: Joi.string()
      .pattern(/^[A-Z]{3}$/i)
      .required()
      .messages({
        'string.pattern.base': '"currencyName" должен содержать ровно 3 заглавные буквы',
        'any.required': '"currencyName" обязателен'
      })
});

const payrollReqSchema = Joi.object({
  bankComment: Joi.string().optional(),
  bankStatus: Joi.string().optional(),
  date: Joi.date().iso().required().messages({
    'date.format': '"date" должна быть в формате YYYY-MM-DD'
  }),
  digestSignatures: Joi.array().items({
    base64Encoded: Joi.string().required(),
    certificateUuid: Joi.string().guid({ version: 'uuidv4' }).required()
  }).optional(),
  number: Joi.string().optional(),
  account: Joi.string().pattern(/^[0-9]{20}$/).optional(),
  admissionValue: Joi.string()
      .pattern(/^[0-9]{2}$/)
      .required()
      .messages({
        'string.pattern.base': 'admissionValue должен содержать ровно 2 цифры',
        'any.required': 'admissionValue обязателен'
      }),
  amount: AmountSchema.required().messages({
    'any.required': 'amount обязателен'
  }),
  authPersonName: Joi.string().max(60).optional(),
  authPersonTelfax: Joi.string().max(40).optional(),
  bic: Joi.string()
      .pattern(/^[0-9]{9}$/)
      .required()
      .messages({
        'string.pattern.base': 'bic должен содержать ровно 9 цифр',
        'any.required': 'bic обязателен'
      }),
  commissionInfo: {
    actualRate: rateSchema,

    actualSum: rateSchema,

    estimatedRate: rateSchema,

    estimatedSum: rateSchema,

    invoiceDate: Joi.date().iso().optional()
  },
  contractDate: Joi.date().iso().required().messages({
    'date.format': '"contractDate" должна быть в формате YYYY-MM-DD',
    'any.required': '"contractDate" обязательна'
  }),
  contractNumber: Joi.string().trim().min(1).required().messages({
    'any.required': '"contractNumber" обязателен'
  }),
  employeeSalaries: Joi.array()
      .items({
        account: Joi.string()
            .pattern(/^[0-9]{20}$/)
            .required()
            .messages({
              'string.pattern.base': 'account должен содержать ровно 20 цифр',
              'any.required': 'account обязателен'
            }),
        amount: AmountSchema.messages({
          'any.required': 'amount обязателен'
        }),
        bankMessage: Joi.string().optional(),
        bic: Joi.string()
            .pattern(/^[0-9]{9}$/)
            .optional()
            .messages({
              'string.pattern.base': 'bic должен содержать ровно 9 цифр'
            }),
        firstName: Joi.string().min(1).required().messages({
          'any.required': 'firstName обязателен'
        }),
        lastName: Joi.string().min(1).required().messages({
          'any.required': 'lastName обязателен'
        }),
        middleName: Joi.string().optional(),
        receiptResult: Joi.string().optional(),
        receiptStatus: Joi.string().optional(),
        result: Joi.string().optional(),
        withheldAmount: Joi.number().positive().optional()
      })
      .min(1)
      .required()
      .messages({
        'array.min': 'employeeSalaries должен содержать хотя бы одного сотрудника',
        'any.required': 'employeeSalaries обязателен'
      }),
  employeesNumber: Joi.number().integer().min(1).required().messages({
    'number.min': 'employeesNumber должно быть >= 1',
    'any.required': 'employeesNumber обязательно'
  }),
  externalId: Joi.string().guid({ version: 'uuidv4' }).required().messages({
    'string.guid': '"externalId" должен быть валидным UUID v4',
    'any.required': '"externalId" обязателен'
  }),
  incomeTypeCode: Joi.string()
      .pattern(/^([1-9]|[1-9][0-9])$/)
      .optional()
      .messages({
        'string.pattern.base': 'incomeTypeCode должен соответствовать формату'
      }),
  loanAmount: AmountSchema.optional(),
  loanDate: Joi.date().iso().optional(),
  loanNumber: Joi.string().max(50).optional(),
  month: Joi.string()
      .min(1)
      .max(50)
      .required()
      .messages({
        'any.required': 'month обязателен'
      }),
  orgName: Joi.string()
      .min(1)
      .max(160)
      .required()
      .messages({
        'any.required': 'orgName обязателен',
        'string.max': 'orgName должен быть не более 160 символов'
      }),
  orgTaxNumber: Joi.string()
      .pattern(/^([0-9]{5}|[0-9]{10}|[0-9]{12}|0)$/)
      .required()
      .messages({
        'string.pattern.base': 'orgTaxNumber должен соответствовать формату',
        'any.required': 'orgTaxNumber обязателен'
      }),
  payDocs: Joi.array().items({
      amount: AmountSchema.messages({
          'any.required': '"amount" обязателен'
      }),

      docDate: Joi.date().iso().required().messages({
          'date.format': '"docDate" должна быть в формате YYYY-MM-DD',
          'any.required': '"docDate" обязательна'
      }),

      number: Joi.string().min(1).required().messages({
          'any.required': '"number" обязателен'
      }),

      payeeAccount: Joi.string()
          .pattern(/^[0-9]{20}$/)
          .required()
          .messages({
              'string.pattern.base': '"payeeAccount" должен содержать ровно 20 цифр',
              'any.required': '"payeeAccount" обязателен'
          }),

      payeeBic: Joi.string()
          .pattern(/^[0-9]{9}$/)
          .required()
          .messages({
              'string.pattern.base': '"payeeBic" должен содержать ровно 9 цифр',
              'any.required': '"payeeBic" обязателен'
          }),

      payerAccount: Joi.string()
          .pattern(/^[0-9]{20}$/)
          .required()
          .messages({
              'string.pattern.base': '"payerAccount" должен содержать ровно 20 цифр',
              'any.required': '"payerAccount" обязателен'
          }),

      payerBic: Joi.string()
          .pattern(/^[0-9]{9}$/)
          .required()
          .messages({
              'string.pattern.base': '"payerBic" должен содержать ровно 9 цифр',
              'any.required': '"payerBic" обязателен'
          }),

      purpose: Joi.string().min(1).required().messages({
          'any.required': '"purpose" обязателен'
      })
  }).optional(),
  year: Joi.string()
      .length(4)
      .required()
      .messages({
        'string.length': 'year должен быть ровно 4 символа',
        'any.required': 'year обязателен'
      })
});

export default { certRequestReqSchema, certRequestReqEIOSchema, paymentReqSchema, payrollReqSchema };
