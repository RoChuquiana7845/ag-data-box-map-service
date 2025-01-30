import { PartialType } from '@nestjs/mapped-types';
import { CreatePixelMapDto } from './create-pixel-map.dto';

export class UpdatePixelMapDto extends PartialType(CreatePixelMapDto) {}
