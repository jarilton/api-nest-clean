import { Module } from '@nestjs/common';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Env } from 'src/env';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: async (
        configService: ConfigService<Env>,
      ): Promise<JwtModuleOptions> => {
        const privateKey = configService.get<string>('JWT_PRIVATE_KEY');
        const publicKey = configService.get<string>('JWT_PUBLIC_KEY');

        if (!privateKey) {
          throw new Error('Chave privada JWT não encontrada.');
        }

        if (!publicKey) {
          throw new Error('Chave pública JWT não encontrada.');
        }

        const ecPrivateKey = Buffer.from(privateKey, 'base64');
        const ecPublicKey = Buffer.from(publicKey, 'base64');

        return {
          privateKey: ecPrivateKey,
          publicKey: ecPublicKey,
          signOptions: {
            algorithm: 'ES256',
            keyid: '1',
          },
        };
      },
    }),
  ],
  providers: [JwtStrategy],
  exports: [JwtModule],
})
export class AuthModule {}
