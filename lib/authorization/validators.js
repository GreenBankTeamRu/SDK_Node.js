import Joi from 'joi';

const authorizationReqSchema = Joi.object({
  grant_type: Joi.string().pattern(/^(authorization_code)$/).required(),
  code: Joi.string().pattern(/^[a-zA-Z0-9]{38}$/).required(),
  client_id: Joi.string().pattern(/^[a-zA-Z0-9]+$/).required(),
  redirect_uri: Joi.string().pattern(/^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})(:[0-9]{1,5})?\/?.*$/).required(),
  client_secret: Joi.string().required(),
  code_verifier: Joi.string(),
  refresh_token: Joi.string()
});

const refreshTokenReqSchema = Joi.object({
  grant_type: Joi.string().pattern(/^(refresh_token)$/).required(),
  client_id: Joi.string().pattern(/^[a-zA-Z0-9]+$/).required(),
  redirect_uri: Joi.string().pattern(/^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})(:[0-9]{1,5})?\/?.*$/).required(),
  client_secret: Joi.string().required(),
  code_verifier: Joi.string(),
  refresh_token: Joi.string()
});

const revokeTokenReqSchema = Joi.object({
  client_id: Joi.string().pattern(/^[a-zA-Z0-9]+$/).required(),
  client_secret: Joi.string().required(),
  token: Joi.string().pattern(/^([a-zA-Z0-9]){38}$/).required(),
  token_type_hint: Joi.string().pattern(/^(access_token|refresh_token)$/).required()
});

const getRefreshClientSecretSchema = Joi.object({
  client_id: Joi.string().pattern(/^[a-zA-Z0-9]+$/).required(),
  client_secret: Joi.string().required(),
  new_client_secret: Joi.string().required()
});


const changeClientSecretSchema = Joi.object({
  access_token: Joi.string().required(),
  client_id: Joi.string().pattern(/^[a-zA-Z0-9]+$/).required(),
  client_secret: Joi.string().required(),
  new_client_secret: Joi.string()
});

export default { authorizationReqSchema, revokeTokenReqSchema, refreshTokenReqSchema, getRefreshClientSecretSchema, changeClientSecretSchema };