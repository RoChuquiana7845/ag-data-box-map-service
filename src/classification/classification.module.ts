import { Module } from '@nestjs/common';
import { ClassificationController } from './classification.controller';
import { ClassificationService } from './classification.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Classification } from './entities/classification.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Classification])],
  controllers: [ClassificationController],
  providers: [ClassificationService],
  exports: [ClassificationService],
})
export class ClassificationModule {}
