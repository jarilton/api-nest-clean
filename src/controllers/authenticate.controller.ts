import {
  Body,
  Controller,
  Post,
  UnauthorizedException,
  UsePipes,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
// import { compare } from 'bcryptjs';
import { ZodValidationPipe } from 'src/pipes/zod-validation-pipe';
import { PrismaService } from 'src/prisma/prisma.service';
import { z } from 'zod';

const authenticateBodySchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

type AuthenticateBodySchema = z.infer<typeof authenticateBodySchema>;

@Controller('/sessions')
export class AuthenticateController {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  @Post()
  @UsePipes(new ZodValidationPipe(authenticateBodySchema))
  async handle(@Body() body: AuthenticateBodySchema) {
    try {
      const { email, password } = body;

      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new UnauthorizedException('User credentials do not match.');
      }

      const isPasswordValid = user.password === password;

      console.log('password', password);
      console.log('ser.password', user.password);
      console.log('isPasswordValid', isPasswordValid);

      if (!isPasswordValid) {
        throw new UnauthorizedException('User credentials do not match.');
      }

      const accessToken = this.jwt.sign({ sub: user.id });

      return {
        access_token: accessToken,
      };
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException('User credentials do not match.');
    }
  }
}
