import { Module } from '@nestjs/common';
import { PixelMapController } from './pixel-map.controller';
import { PixelMapService } from './pixel-map.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PixelMap } from './entities/pixel-map.entity';

@Module({
  imports: [TypeOrmModule.forFeature([PixelMap])],
  controllers: [PixelMapController],
  providers: [PixelMapService],
  exports: [PixelMapService],
})
export class PixelMapModule {}
