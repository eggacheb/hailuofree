import Request from '@/lib/request/Request.ts';
import Response from '@/lib/response/Response.ts';
import tokenManager from '@/lib/token-manager.ts';
import { refreshToken } from '@/api/controllers/token-utils.ts';
import config from '@/lib/config.ts';
import logger from '@/lib/logger.ts';
import APIException from '@/lib/exceptions/APIException.ts';
import EX from '@/api/consts/exceptions.ts';

export default {
    prefix: '/v1',
    post: {
        '/token': async (request: Request) => {
            try {
                // 验证API密钥
                const apiKey = request.get('authorization')?.replace('Bearer ', '');
                if (apiKey !== config.apiKey) {
                    throw new APIException(EX.API_UNAUTHORIZED, 'Invalid API key');
                }

                const body = await request.json();
                let tokens = body.tokens || body.token;

                if (!tokens) {
                    throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'Tokens are required');
                }

                // 处理不同的输入格式
                if (typeof tokens === 'string') {
                    // 处理 "token1,token2,token3" 格式或单个token
                    tokens = tokens.includes(',') ? tokens.split(',').map(t => t.trim()) : [tokens];
                } else if (!Array.isArray(tokens)) {
                    throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'Tokens must be a string or an array');
                }

                const results = [];

                for (const token of tokens) {
                    if (typeof token !== 'string') {
                        throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'Each token must be a string');
                    }

                    try {
                        const newToken = await refreshToken(token);
                        if (newToken) {
                            await tokenManager.updateToken(token, newToken);
                            results.push({ oldToken: token, newToken, status: 'success' });
                        } else {
                            results.push({ oldToken: token, status: 'failed', message: 'Failed to refresh token' });
                        }
                    } catch (error) {
                        logger.error(`Failed to refresh token: ${error.message}`);
                        results.push({ oldToken: token, status: 'failed', message: error.message });
                    }
                }

                return new Response({
                    message: 'Token操作完成',
                    tokenCount: tokenManager.getTokenCount(),
                    results
                });
            } catch (error) {
                if (error instanceof APIException) {
                    throw error;
                }
                logger.error(`Error in /token route: ${error.message}`);
                throw new APIException(EX.API_UNKNOWN_ERROR, 'An unexpected error occurred');
            }
        }
    },
    get: {
        '/token/refresh': async (request: Request) => {
            try {
                // 验证API密钥
                const apiKey = request.get('authorization')?.replace('Bearer ', '');
                if (apiKey !== config.apiKey) {
                    throw new APIException(EX.API_UNAUTHORIZED, 'Invalid API key');
                }

                await tokenManager.refreshTokens();
                const status = tokenManager.getRefreshStatus();

                return new Response({
                    message: '刷新成功',
                    tokenCount: tokenManager.getTokenCount(),
                    status
                });
            } catch (error) {
                if (error instanceof APIException) {
                    throw error;
                }
                logger.error(`Error in /token/refresh route: ${error.message}`);
                throw new APIException(EX.API_UNKNOWN_ERROR, 'An unexpected error occurred');
            }
        }
    }
};
