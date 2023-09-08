import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { OAuthComponent } from './oauth.component';

const routes: Routes = [
  {
    path: '',
    component: OAuthComponent,
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class OAuthRoutingModule { }
