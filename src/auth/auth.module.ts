import { Module } from '@nestjs/common';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Env } from 'src/env';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: async (
        configService: ConfigService<Env>,
      ): Promise<JwtModuleOptions> => {
        const privateKey = configService.get<string>('JWT_PRIVATE_KEY');

        if (!privateKey) {
          throw new Error('Chave privada JWT não encontrada.');
        }

        const ecPrivateKey = Buffer.from(privateKey, 'base64');

        return {
          privateKey: ecPrivateKey,
          signOptions: {
            algorithm: 'ES256',
            keyid: '1',
          },
        };
      },
    }),
  ],
  exports: [JwtModule],
})
export class AuthModule {}
