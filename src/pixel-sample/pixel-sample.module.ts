import { Module } from '@nestjs/common';
import { PixelSampleController } from './pixel-sample.controller';
import { PixelSampleService } from './pixel-sample.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PixelSample } from './entities/pixel-sample.entity';

@Module({
  imports: [TypeOrmModule.forFeature([PixelSample])],
  controllers: [PixelSampleController],
  providers: [PixelSampleService],
  exports: [PixelSampleService],
})
export class PixelSampleModule {}
