import { PartialType } from '@nestjs/mapped-types';
import { CreatePixelSampleDto } from './create-pixel-sample.dto';

export class UpdatePixelSampleDto extends PartialType(CreatePixelSampleDto) {}
